import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import type { Capability, Device, MatrixData, Policy, Snapshot } from "../types";


const EMPTY_MATRIX: MatrixData = { snapshot_id: null, segments: [], cells: [] };


export function useAppData(activePage = "matrix") {
  const [matrix, setMatrix] = useState<MatrixData>(EMPTY_MATRIX);
  const [devices, setDevices] = useState<Device[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [debug, setDebug] = useState<any[]>([]);
  const [debugLoading, setDebugLoading] = useState(false);
  const [debugError, setDebugError] = useState("");
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [protocol, setProtocol] = useState("");
  const [port, setPort] = useState("");
  const [error, setError] = useState("");
  const [matrixError, setMatrixError] = useState("");
  const [matrixLoading, setMatrixLoading] = useState(false);
  const matrixRequest = useRef(0);
  const [refreshIndex, setRefreshIndex] = useState(0);

  const [snapshotId, setSnapshotId] = useState(() => {
    try { return localStorage.getItem("netpolicy-snapshot") || ""; } catch { return ""; }
  });
  const refreshRequest = useRef(0);
  const refresh = async (requestedId = snapshotId) => {
    const request = ++refreshRequest.current;
    setRefreshIndex(value => value + 1);
    setLoading(true);
    setMatrix(EMPTY_MATRIX); setDevices([]); setPolicies([]); setDebug([]);
    setError(""); setMatrixError("");
    try {
      const snapshotData = await api.snapshots();
      if (request !== refreshRequest.current) return;
      const id = snapshotData.some(s => s.id === requestedId) ? requestedId : snapshotData[0]?.id || "";
      setSnapshots(snapshotData); setSnapshotId(id);
      try { if (id) localStorage.setItem("netpolicy-snapshot", id); else localStorage.removeItem("netpolicy-snapshot"); } catch {}
      const [deviceData, policyData, capabilityData] = await Promise.all([
        api.devices(id), api.policies(id), api.capabilities(),
      ]);
      if (request !== refreshRequest.current) return;
      setDevices(deviceData.items); setPolicies(policyData.items); setCapabilities(capabilityData);
    } catch (cause) {
      if (request === refreshRequest.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (request === refreshRequest.current) setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const request = ++matrixRequest.current;
    setMatrixLoading(true);
    setMatrixError("");
    const timer = setTimeout(async () => {
      try {
        const value = await api.matrix(protocol, port, controller.signal, snapshotId);
        if (request === matrixRequest.current) setMatrix(value);
      } catch (cause) {
        if (request === matrixRequest.current)
          setMatrixError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (request === matrixRequest.current) setMatrixLoading(false);
      }
    }, 250);
    return () => {
      controller.abort();
      clearTimeout(timer);
      if (request === matrixRequest.current) matrixRequest.current++;
    };
  }, [protocol, port, refreshIndex, snapshotId]);

  useEffect(() => {
    if (activePage !== "debug") return;
    const controller = new AbortController();
    setDebugLoading(true);
    setDebugError("");
    api.debug(controller.signal, snapshotId).then(value => {
      if (!controller.signal.aborted) setDebug(value.items);
    }).catch(cause => {
      if (!controller.signal.aborted) setDebugError(String(cause.message || cause));
    }).finally(() => {
      if (!controller.signal.aborted) setDebugLoading(false);
    });
    return () => controller.abort();
  }, [activePage, refreshIndex, snapshotId]);

  const loadSample = async () => {
    await api.sample();
    await refresh("");
  };

  return {
    matrix, devices, policies, capabilities, debug, snapshots, loading: loading || matrixLoading,
    protocol, setProtocol, port, setPort, error: (activePage === "debug" ? debugError : matrixError) || error, refresh, loadSample, debugLoading,
    revision: refreshIndex, snapshotId, selectSnapshot: refresh, snapshotLoading: loading,
  };
}
