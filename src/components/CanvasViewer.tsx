import { useRef, useEffect, useState, useCallback } from "react";
import { type ReactZoomPanPinchRef, TransformComponent, TransformWrapper } from "react-zoom-pan-pinch";
import { Minus, RotateCcw, Plus } from "lucide-react";

interface CanvasViewerProps {
  imageUrl: string;
  overlayText?: string | null;
}

export default function CanvasViewer({ imageUrl, overlayText }: CanvasViewerProps) {
  const transformRef = useRef<ReactZoomPanPinchRef>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [showScaleIndicator, setShowScaleIndicator] = useState(false);
  const indicatorTimeoutRef = useRef<number | null>(null);

  const showIndicator = useCallback(() => {
    setShowScaleIndicator(true);
    if (indicatorTimeoutRef.current !== null) {
      clearTimeout(indicatorTimeoutRef.current);
    }
    indicatorTimeoutRef.current = window.setTimeout(() => {
      setShowScaleIndicator(false);
    }, 800);
  }, []);

  // 自定义滚轮缩放：以鼠标位置为中心，带平滑过渡
  useEffect(() => {
    const container = containerRef.current;
    if (!container || !transformRef.current) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();

      const api = transformRef.current;
      if (!api?.state || !api?.instance) return;

      const state = api.state;
      const delta = -e.deltaY * 0.0025;
      const scaleFactor = 1 + delta;
      const newScale = Math.min(Math.max(state.scale * scaleFactor, 0.05), 8);

      // 以鼠标位置为中心缩放
      const rect = container.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const scaleDiff = newScale - state.scale;

      const newPositionX = state.positionX - (mouseX - state.positionX) * (scaleDiff / state.scale);
      const newPositionY = state.positionY - (mouseY - state.positionY) * (scaleDiff / state.scale);

      api.setTransform(newPositionX, newPositionY, newScale, 120, "easeOut");
      showIndicator();
    };

    container.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      container.removeEventListener("wheel", handleWheel);
      if (indicatorTimeoutRef.current !== null) {
        clearTimeout(indicatorTimeoutRef.current);
      }
    };
  }, [showIndicator]);

  return (
    <div ref={containerRef} className="relative h-full w-full overflow-hidden">
      {/* 网格背景 */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `repeating-linear-gradient(0deg, color-mix(in oklab, var(--separator) 60%, transparent) 0px, color-mix(in oklab, var(--separator) 60%, transparent) 1px, transparent 1px, transparent 20px), repeating-linear-gradient(90deg, color-mix(in oklab, var(--separator) 60%, transparent) 0px, color-mix(in oklab, var(--separator) 60%, transparent) 1px, transparent 1px, transparent 20px)`,
        }}
      />

      {/* 缩放比例提示 */}
      <div
        className="pointer-events-none absolute left-3 top-3 z-50 rounded-md px-2 py-1 text-[11px] font-medium"
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          color: "var(--foreground)",
          opacity: showScaleIndicator ? 1 : 0,
          transform: showScaleIndicator ? "translateY(0)" : "translateY(-6px)",
          transition: "opacity 0.2s ease, transform 0.2s ease",
        }}
      >
        {Math.round((transformRef.current?.state.scale ?? 1) * 100)}%
      </div>

      <TransformWrapper
        ref={transformRef}
        initialScale={1}
        minScale={0.05}
        maxScale={8}
        centerOnInit
        limitToBounds={false}
        wheel={{ disabled: true }}
        panning={{ velocityDisabled: false }}
        doubleClick={{ disabled: true }}
      >
        {({ zoomIn, zoomOut, resetTransform }) => (
          <>
            {/* Zoom Controls */}
            <div
              className="absolute bottom-4 left-1/2 z-10 flex -translate-x-1/2 items-center gap-1 rounded-lg px-2 py-1 shadow-lg"
              style={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
              }}
            >
              <button
                onClick={() => {
                  zoomOut(0.15);
                  showIndicator();
                }}
                className="flex h-7 w-7 items-center justify-center rounded transition-micro hover:opacity-80"
                style={{ color: "var(--foreground)" }}
                title="缩小"
              >
                <Minus size={14} />
              </button>
              <button
                onClick={() => {
                  resetTransform(300, "easeOut");
                  showIndicator();
                }}
                className="flex h-7 w-7 items-center justify-center rounded transition-micro hover:opacity-80"
                style={{ color: "var(--foreground)" }}
                title="重置"
              >
                <RotateCcw size={14} />
              </button>
              <button
                onClick={() => {
                  zoomIn(0.15);
                  showIndicator();
                }}
                className="flex h-7 w-7 items-center justify-center rounded transition-micro hover:opacity-80"
                style={{ color: "var(--foreground)" }}
                title="放大"
              >
                <Plus size={14} />
              </button>
            </div>

            <TransformComponent
              wrapperClass="w-full! h-full!"
              contentClass="w-full! h-full! flex items-center justify-center"
              contentStyle={{
                transition: "transform 0.12s ease-out",
                willChange: "transform",
              }}
            >
              <img
                src={imageUrl}
                alt="预览"
                className="max-h-full max-w-full object-contain"
                draggable={false}
                style={{ imageRendering: "auto" }}
              />
            </TransformComponent>
          </>
        )}
      </TransformWrapper>

      {/* Text Overlay */}
      {overlayText && (
        <div
          className="absolute right-4 top-4 z-10 max-w-xs rounded-lg px-4 py-3 shadow-lg"
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
          }}
        >
          <pre
            className="whitespace-pre-wrap font-mono text-xs leading-relaxed"
            style={{ color: "var(--foreground)" }}
          >
            {overlayText}
          </pre>
        </div>
      )}
    </div>
  );
}
