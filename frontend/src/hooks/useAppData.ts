import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import type { Capability, Device, MatrixData, Policy, Snapshot } from "../types";


const EMPTY_MATRIX: MatrixData = { snapshot_id: null, segments: [], cells: [] };


export function useAppData() {
  const [matrix, setMatrix] = useState<MatrixData>(EMPTY_MATRIX);
  const [devices, setDevices] = useState<Device[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [debug, setDebug] = useState<any[]>([]);
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
      const [deviceData, policyData, capabilityData, debugData, snapshotData] =
        await Promise.all([
          api.devices(), api.policies(),
          api.capabilities(), api.debug(), api.snapshots(),
        ]);
      setDevices(deviceData.items);
      setPolicies(policyData.items);
      setCapabilities(capabilityData);
      setDebug(debugData.items);
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
    const request = ++matrixRequest.current;
    setMatrixLoading(true);
    setMatrixError("");
    const timer = setTimeout(async () => {
      try {
        const value = await api.matrix(protocol, port);
        if (request === matrixRequest.current) setMatrix(value);
      } catch (cause) {
        if (request === matrixRequest.current)
          setMatrixError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (request === matrixRequest.current) setMatrixLoading(false);
      }
    }, 250);
    return () => {
      clearTimeout(timer);
      if (request === matrixRequest.current) matrixRequest.current++;
    };
  }, [protocol, port, refreshIndex]);

  const loadSample = async () => {
    await api.sample();
    await refresh();
  };

  return {
    matrix, devices, policies, capabilities, debug, snapshots, loading: loading || matrixLoading,
    protocol, setProtocol, port, setPort, error: matrixError || error, refresh, loadSample,
    revision: refreshIndex,
  };
}
