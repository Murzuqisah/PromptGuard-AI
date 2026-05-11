import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "@/components/Layout";
import ScannerPage from "@/pages/Scanner";
import AuditPage from "@/pages/Audit";
import PolicyPage from "@/pages/Policy";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<ScannerPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="policy" element={<PolicyPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
