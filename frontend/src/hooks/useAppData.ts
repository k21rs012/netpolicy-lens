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

  const refresh = async () => {
    setRefreshIndex(value => value + 1);
    setLoading(true);
    setError("");
    setMatrixError("");
    try {
      const [deviceData, policyData, capabilityData, snapshotData] =
        await Promise.all([
          api.devices(), api.policies(),
          api.capabilities(), api.snapshots(),
        ]);
      setDevices(deviceData.items);
      setPolicies(policyData.items);
      setCapabilities(capabilityData);
      setSnapshots(snapshotData);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
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
        const value = await api.matrix(protocol, port, controller.signal);
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
  }, [protocol, port, refreshIndex]);

  useEffect(() => {
    if (activePage !== "debug") return;
    const controller = new AbortController();
    setDebugLoading(true);
    setDebugError("");
    api.debug(controller.signal).then(value => {
      if (!controller.signal.aborted) setDebug(value.items);
    }).catch(cause => {
      if (!controller.signal.aborted) setDebugError(String(cause.message || cause));
    }).finally(() => {
      if (!controller.signal.aborted) setDebugLoading(false);
    });
    return () => controller.abort();
  }, [activePage, refreshIndex]);

  const loadSample = async () => {
    await api.sample();
    await refresh();
  };

  return {
    matrix, devices, policies, capabilities, debug, snapshots, loading: loading || matrixLoading,
    protocol, setProtocol, port, setPort, error: (activePage === "debug" ? debugError : matrixError) || error, refresh, loadSample, debugLoading,
    revision: refreshIndex,
  };
}
