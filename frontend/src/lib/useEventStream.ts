import { useEffect, useRef, useState, useCallback } from "react";
import type { ScanResult } from "@/lib/scanner";

const _base = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const WS_URL = _base ? _base.replace(/^http/, "ws") + "/ws/events" : `ws://${window.location.host}/ws/events`;

export function useEventStream() {
  const [events, setEvents] = useState<ScanResult[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimer.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as ScanResult;
          setEvents((prev) => [event, ...prev].slice(0, 50));
        } catch { /* ignore malformed */ }
      };
    } catch {
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connect]);

  return { events, connected };
}
