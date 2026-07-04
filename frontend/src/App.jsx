import { Routes, Route, Navigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { useLocation } from "react-router-dom";
import { lazy, Suspense } from "react";
import TopNav from "./components/layout/TopNav.jsx";
import ToastStack from "./components/common/Toasts.jsx";
import CriticalAlertModal from "./components/common/CriticalAlertModal.jsx";
import { SkeletonPage } from "./components/common/Skeleton.jsx";

// Route-level code splitting — Syndicate (d3) and Report (recharts) are the
// heaviest pages; lazy-loading them keeps the initial bundle to what the
// wizard/upload/analysis flow actually needs.
const CaseSetupWizard = lazy(() => import("./pages/CaseSetupWizard.jsx"));
const Upload = lazy(() => import("./pages/Upload.jsx"));
const Analysis = lazy(() => import("./pages/Analysis.jsx"));
const Report = lazy(() => import("./pages/Report.jsx"));
const Syndicate = lazy(() => import("./pages/Syndicate.jsx"));
const JarmBridge = lazy(() => import("./pages/JarmBridge.jsx"));
const EvidenceLocker = lazy(() => import("./pages/EvidenceLocker.jsx"));

function PageTransition({ children }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}

export default function App() {
  const location = useLocation();

  return (
    <div className="min-h-screen">
      <TopNav />
      <ToastStack />
      <CriticalAlertModal />
      <Suspense fallback={<SkeletonPage />}>
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route path="/" element={<Navigate to="/setup" replace />} />
            <Route path="/setup" element={<PageTransition><CaseSetupWizard /></PageTransition>} />
            <Route path="/upload" element={<PageTransition><Upload /></PageTransition>} />
            <Route path="/analysis/:id" element={<PageTransition><Analysis /></PageTransition>} />
            <Route path="/report/:id" element={<PageTransition><Report /></PageTransition>} />
            <Route path="/syndicate" element={<PageTransition><Syndicate /></PageTransition>} />
            <Route path="/jarm" element={<PageTransition><JarmBridge /></PageTransition>} />
            <Route path="/evidence" element={<PageTransition><EvidenceLocker /></PageTransition>} />
          </Routes>
        </AnimatePresence>
      </Suspense>
    </div>
  );
}
