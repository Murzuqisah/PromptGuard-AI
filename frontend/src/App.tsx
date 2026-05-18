import { useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "@/components/Layout";
import ErrorBoundary from "@/components/ErrorBoundary";
import SplashScreen from "@/components/SplashScreen";
import AlertToasts from "@/components/AlertToasts";
import ScannerPage from "@/pages/Scanner";
import AuditPage from "@/pages/Audit";
import PolicyPage from "@/pages/Policy";
import NotFound from "@/pages/NotFound";
import { useEventStream } from "@/lib/useEventStream";

export default function App() {
  const [showSplash, setShowSplash] = useState(true);
  const { events } = useEventStream();

  return (
    <ErrorBoundary>
      {showSplash && <SplashScreen onComplete={() => setShowSplash(false)} />}
      <AlertToasts events={events} />
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<ScannerPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="policy" element={<PolicyPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
