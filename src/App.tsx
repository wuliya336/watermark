import { useState, useCallback, useRef, useEffect } from "react";
import { Tabs } from "@heroui/react";
import { gsap } from "gsap";
import { Layers, Image } from "lucide-react";
import ImageSection from "./components/ImageSection";
import EmbedControls from "./components/EmbedControls";
import ExtractControls from "./components/ExtractControls";
import CanvasViewer from "./components/CanvasViewer";
import { getImageFileInfo, type ImageFileInfo } from "./utils/fileInfo";
import type { ResultData } from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState("embed");
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [fileInfo, setFileInfo] = useState<ImageFileInfo | null>(null);
  const [result, setResult] = useState<ResultData | null>(null);
  const [wmSize, setWmSize] = useState(0);

  const canvasRef = useRef<HTMLDivElement>(null);
  const embedRef = useRef<HTMLDivElement>(null);
  const extractRef = useRef<HTMLDivElement>(null);

  // Initialize GSAP positions
  useEffect(() => {
    if (embedRef.current && extractRef.current) {
      gsap.set(embedRef.current, { x: 0, opacity: 1 });
      gsap.set(extractRef.current, { x: 60, opacity: 0 });
    }
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    return false;
  }, []);

  const handleFileSelect = useCallback(async (selectedFile: File, url: string) => {
    setFile(selectedFile);
    setPreviewUrl(url);
    setResult(null);
    const info = await getImageFileInfo(selectedFile);
    setFileInfo(info);

    if (canvasRef.current) {
      gsap.fromTo(
        canvasRef.current,
        { opacity: 0.6 },
        { opacity: 1, duration: 0.4, ease: "power2.out" }
      );
    }
  }, []);

  const handleClear = useCallback(() => {
    setFile(null);
    setPreviewUrl("");
    setFileInfo(null);
    setResult(null);
    setWmSize(0);
  }, []);

  const handleResult = useCallback((newResult: ResultData) => {
    setResult(newResult);
    if (newResult.type === "image") {
      setWmSize(newResult.wmSize);
    }

    if (canvasRef.current) {
      gsap.fromTo(
        canvasRef.current.querySelector("img"),
        { scale: 0.95, opacity: 0.5 },
        { scale: 1, opacity: 1, duration: 0.5, ease: "power2.out" }
      );
    }
  }, []);

  const handleTabChange = useCallback(
    (key: string) => {
      if (key === activeTab) return;

      const isForward = key === "extract"; // embed -> extract
      const currentRef = activeTab === "embed" ? embedRef.current : extractRef.current;
      const nextRef = key === "embed" ? embedRef.current : extractRef.current;
      if (!currentRef || !nextRef) return;

      // Kill any running animations to allow rapid switching
      gsap.killTweensOf([currentRef, nextRef]);

      setActiveTab(key);
      setResult(null);

      const outX = isForward ? -60 : 60;
      const inX = isForward ? 60 : -60;

      // Current slides out
      gsap.to(currentRef, {
        x: outX,
        opacity: 0,
        duration: 0.2,
        ease: "power2.in",
        overwrite: true,
      });

      // Next slides in
      gsap.fromTo(
        nextRef,
        { x: inX, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 0.25,
          ease: "power2.out",
          overwrite: true,
          delay: 0.05,
        }
      );
    },
    [activeTab]
  );

  // Determine what to show in canvas
  const canvasImageUrl = result?.type === "image" ? result.dataUrl : previewUrl;

  return (
    <div
      className="flex h-screen w-screen flex-col overflow-hidden"
      onContextMenu={handleContextMenu}
      style={{ background: "var(--background)" }}
    >
      {/* Title Bar */}
      <header
        className="flex shrink-0 items-center justify-between px-5 py-2.5"
        style={{
          borderBottom: "1px solid var(--border)",
          WebkitAppRegion: "drag",
        } as React.CSSProperties}
      >
        <div className="flex items-center gap-2.5">
          <div
            className="flex h-5 w-5 items-center justify-center rounded-sm"
            style={{ background: "var(--foreground)", color: "var(--background)" }}
          >
            <Layers size={12} strokeWidth={2.5} />
          </div>
          <div className="flex items-baseline gap-2">
            <h1 className="text-[13px] font-semibold tracking-tight">Watermark Tool</h1>
            <span className="text-[10px]" style={{ color: "var(--muted)" }}>
              数字水印工具
            </span>
          </div>
        </div>
        <span
          className="font-mono-nums text-[10px]"
          style={{ color: "var(--muted-secondary)" }}
        >
          v1.0.11
        </span>
      </header>

      {/* Main Content */}
      <main className="flex flex-1 overflow-hidden">
        {/* Left Panel - Controls */}
        <aside
          className="flex w-[400px] shrink-0 flex-col overflow-hidden"
          style={{ borderRight: "1px solid var(--border)" }}
        >
          {/* Tabs */}
          <Tabs
            variant="secondary"
            selectedKey={activeTab}
            onSelectionChange={(key) => handleTabChange(key as string)}
            className="w-full shrink-0"
          >
            <Tabs.ListContainer>
              <Tabs.List aria-label="水印操作" className="w-full">
                <Tabs.Tab id="embed" className="flex-1 text-center text-[13px]">
                  嵌入水印
                  <Tabs.Indicator />
                </Tabs.Tab>
                <Tabs.Tab id="extract" className="flex-1 text-center text-[13px]">
                  提取水印
                  <Tabs.Indicator />
                </Tabs.Tab>
              </Tabs.List>
            </Tabs.ListContainer>
          </Tabs>

          {/* Panel Content */}
          <div className="flex flex-1 flex-col gap-3 overflow-hidden p-4">
            {/* Fixed: Image Upload + Info */}
            <ImageSection
              file={file}
              previewUrl={previewUrl}
              fileInfo={fileInfo}
              onFileSelect={handleFileSelect}
              onClear={handleClear}
            />

            {/* Animated: Controls */}
            <div className="relative flex-1 overflow-hidden">
              <div
                ref={embedRef}
                className="absolute inset-0"
                style={{ zIndex: activeTab === "embed" ? 1 : 0 }}
              >
                <EmbedControls
                  file={file}
                  result={result}
                  onResult={handleResult}
                />
              </div>
              <div
                ref={extractRef}
                className="absolute inset-0"
                style={{ zIndex: activeTab === "extract" ? 1 : 0 }}
              >
                <ExtractControls
                  file={file}
                  result={result}
                  wmSize={wmSize}
                  onResult={handleResult}
                />
              </div>
            </div>
          </div>
        </aside>

        {/* Right Panel - Canvas */}
        <section
          ref={canvasRef}
          className="relative flex flex-1 flex-col overflow-hidden"
          style={{ background: "var(--surface-secondary)" }}
        >
          {canvasImageUrl ? (
            <CanvasViewer imageUrl={canvasImageUrl} />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-3" style={{ color: "var(--muted)" }}>
              <Image size={40} strokeWidth={1} className="animate-pulse-soft" />
              <p className="text-sm">在左侧面板选择图片</p>
              <p className="text-xs" style={{ color: "var(--muted-secondary)" }}>
                支持 PNG、JPEG、BMP、WebP 格式
              </p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
