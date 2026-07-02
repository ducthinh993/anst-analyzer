/**
 * gRPC service implementations for the js-reachability plugin.
 *
 * Registers four services on the provided grpc.Server — all four are required
 * for a clean go-plugin v1.8.0 lifecycle:
 *
 *   1. grpc.health.v1.Health   — go-plugin Ping() calls Health/Check with service="plugin";
 *                                must return SERVING or the connection fails.
 *   2. commit0.v1.Analyzer        — the actual plugin contract (Metadata + Analyze).
 *   3. plugin.GRPCController   — Shutdown(); without it Kill() waits the 2-second grace period.
 *   4. plugin.GRPCStdio        — StreamStdio no-op; without it go-plugin logs Unimplemented.
 *
 * Proto files for the auxiliary go-plugin services are embedded at build time
 * via import assertions (type: "text") so the compiled binary is self-contained.
 * grpc_stdio.proto imports google/protobuf/empty.proto; that import is satisfied
 * by writing both protos to a temp directory at startup so proto-loader can
 * resolve relative imports correctly.
 */

import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {
  AnalyzerService,
  type AnalyzerServer,
  type MetadataRequest,
  type MetadataResponse,
  type AnalyzeRequest,
} from "./gen/commit0/v1/plugin.js";
import type { Finding } from "./gen/commit0/v1/plugin.js";
import { analyze } from "./engine/analyze.js";

// Proto file contents are embedded at compile time so the binary is fully
// self-contained (no dependency on files alongside the binary).
import grpcHealthProtoText from "../proto/grpc_health.proto" with { type: "text" };
import grpcControllerProtoText from "../proto/grpc_controller.proto" with { type: "text" };
import grpcStdioProtoText from "../proto/grpc_stdio.proto" with { type: "text" };
import grpcBrokerProtoText from "../proto/grpc_broker.proto" with { type: "text" };

// google/protobuf/empty.proto is needed by grpc_stdio.proto.
// We include the minimal definition needed for the service (no methods, just the message).
const googleProtobufEmptyProtoText = `
syntax = "proto3";
package google.protobuf;
option go_package = "google.golang.org/protobuf/types/known/emptypb";
message Empty {}
`;

// Contract version this plugin implements. The host accepts any plugin whose
// major matches and whose minor is <= the host's (contract.Compatible), so this
// stays at the minor this plugin actually implements — it does not need to
// track the host's latest minor.
const PROTOCOL_VERSION = "0.1";
const PLUGIN_VERSION = "0.1.0";
const PLUGIN_NAME = "js-reachability";

// ─── Analyzer implementation ──────────────────────────────────────────────────

const analyzerImpl: AnalyzerServer = {
  metadata(
    call: grpc.ServerUnaryCall<MetadataRequest, MetadataResponse>,
    callback: grpc.sendUnaryData<MetadataResponse>,
  ): void {
    callback(null, {
      name: PLUGIN_NAME,
      version: PLUGIN_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      description: "JS/TS SCA reachability analyzer for commit0-analyzer",
      supportedLanguages: ["js", "ts"],
    });
  },

  analyze(
    call: grpc.ServerWritableStream<AnalyzeRequest, Finding>,
  ): void {
    const req = call.request;
    analyze({
      moduleRoot: req.moduleRoot,
      entrypoints: req.entrypoints,
      advisories: req.advisories,
    })
      .then((findings) => {
        // Stream findings eagerly — do not buffer.
        for (const f of findings) {
          call.write(f);
        }
        call.end();
      })
      .catch((err: unknown) => {
        call.destroy(
          Object.assign(new Error(String(err)), { code: grpc.status.INTERNAL }),
        );
      });
  },
};

// ─── Auxiliary go-plugin services ────────────────────────────────────────────

/**
 * Returns the directory containing the proto files, creating a temp directory
 * with embedded content if running as a compiled binary (where the source
 * proto/ directory is not present on disk).
 *
 * The temp directory is created once lazily and reused for the process lifetime.
 * It is not cleaned up on exit; the OS will reclaim it after process exit.
 */
let _protoTempDir: string | null = null;

function protoDir(): string {
  if (_protoTempDir !== null) {
    return _protoTempDir;
  }

  // Try the source-tree proto directory first (development / test mode).
  // import.meta.url points to the real source file when running via node/bun run.
  try {
    const sourceProto = path.resolve(
      path.dirname(new URL(import.meta.url).pathname),
      "../proto",
    );
    if (fs.existsSync(path.join(sourceProto, "grpc_health.proto"))) {
      _protoTempDir = sourceProto;
      return _protoTempDir;
    }
  } catch {
    // import.meta.url may not be a file:// URL in compiled mode; fall through.
  }

  // Compiled binary mode: write embedded proto content to a temp directory.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "commit0-analyzer-proto-"));

  // Create the google/protobuf/ subdirectory for the empty.proto import.
  const googleProtobufDir = path.join(tmpDir, "google", "protobuf");
  fs.mkdirSync(googleProtobufDir, { recursive: true });

  fs.writeFileSync(path.join(tmpDir, "grpc_health.proto"), grpcHealthProtoText);
  fs.writeFileSync(path.join(tmpDir, "grpc_controller.proto"), grpcControllerProtoText);
  fs.writeFileSync(path.join(tmpDir, "grpc_stdio.proto"), grpcStdioProtoText);
  fs.writeFileSync(path.join(tmpDir, "grpc_broker.proto"), grpcBrokerProtoText);
  fs.writeFileSync(path.join(googleProtobufDir, "empty.proto"), googleProtobufEmptyProtoText);

  _protoTempDir = tmpDir;
  return tmpDir;
}

function loadProto(filename: string): grpc.GrpcObject {
  const dir = protoDir();
  const protoPath = path.join(dir, filename);
  const packageDef = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [dir],
  });
  return grpc.loadPackageDefinition(packageDef);
}

/**
 * Registers all four required gRPC services on the given server.
 * Returns the server for chaining.
 */
export function registerServices(server: grpc.Server): grpc.Server {
  // 1. commit0.v1.Analyzer (generated stubs used directly for type safety)
  server.addService(AnalyzerService, analyzerImpl as unknown as grpc.UntypedServiceImplementation);

  // 2. grpc.health.v1.Health
  const healthPkg = loadProto("grpc_health.proto") as unknown as Record<string, Record<string, Record<string, Record<string, grpc.ServiceClientConstructor>>>>;
  const HealthService = healthPkg["grpc"]?.["health"]?.["v1"]?.["Health"]?.service;
  if (HealthService) {
    server.addService(HealthService, {
      check(
        _call: grpc.ServerUnaryCall<unknown, unknown>,
        callback: grpc.sendUnaryData<unknown>,
      ) {
        // go-plugin Ping() checks service="plugin"; always report SERVING.
        callback(null, { status: "SERVING" });
      },
      watch(call: grpc.ServerWritableStream<unknown, unknown>) {
        // Not used by go-plugin; close immediately.
        call.end();
      },
    });
  }

  // 3. plugin.GRPCController
  const controllerPkg = loadProto("grpc_controller.proto") as unknown as Record<string, Record<string, grpc.ServiceClientConstructor>>;
  const ControllerService = controllerPkg["plugin"]?.["GRPCController"]?.service;
  if (ControllerService) {
    server.addService(ControllerService, {
      shutdown(
        _call: grpc.ServerUnaryCall<unknown, unknown>,
        callback: grpc.sendUnaryData<unknown>,
      ) {
        callback(null, {});
        // Give the response a moment to flush before shutting down.
        setImmediate(() => process.exit(0));
      },
    });
  }

  // 4. plugin.GRPCStdio (no-op; suppresses Unimplemented warning in go-plugin logs)
  const stdioPkg = loadProto("grpc_stdio.proto") as unknown as Record<string, Record<string, grpc.ServiceClientConstructor>>;
  const StdioService = stdioPkg["plugin"]?.["GRPCStdio"]?.service;
  if (StdioService) {
    server.addService(StdioService, {
      streamStdio(call: grpc.ServerWritableStream<unknown, unknown>) {
        // No stdio to relay; close the stream cleanly.
        call.end();
      },
    });
  }

  // 5. plugin.GRPCBroker — bidirectional stream used by go-plugin for secondary
  //    gRPC connections. The go-plugin client unconditionally opens a broker
  //    StartStream on connect; a no-op server suppresses the Unimplemented error
  //    (same rationale as GRPCStdio above). This plugin never opens secondary
  //    connections, so we drain incoming ConnInfo messages and keep the stream
  //    open until the client cancels it.
  const brokerPkg = loadProto("grpc_broker.proto") as unknown as Record<string, Record<string, grpc.ServiceClientConstructor>>;
  const BrokerService = brokerPkg["plugin"]?.["GRPCBroker"]?.service;
  if (BrokerService) {
    server.addService(BrokerService, {
      startStream(call: grpc.ServerDuplexStream<unknown, unknown>) {
        // Drain incoming ConnInfo messages and wait for the client to close.
        call.on("data", () => { /* discard */ });
        call.on("end", () => { call.end(); });
      },
    });
  }

  return server;
}
