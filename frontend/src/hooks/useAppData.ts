import { useEffect, useState } from "react";

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

  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      const [matrixData, deviceData, policyData, capabilityData, debugData, snapshotData] =
        await Promise.all([
          api.matrix(protocol, port), api.devices(), api.policies(),
          api.capabilities(), api.debug(), api.snapshots(),
        ]);
      setMatrix(matrixData);
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
    const timer = setTimeout(() => {
      api.matrix(protocol, port).then(setMatrix).catch(() => {});
    }, 250);
    return () => clearTimeout(timer);
  }, [protocol, port]);

  const loadSample = async () => {
    await api.sample();
    await refresh();
  };

  return {
    matrix, devices, policies, capabilities, debug, snapshots, loading,
    protocol, setProtocol, port, setPort, error, refresh, loadSample,
  };
}
