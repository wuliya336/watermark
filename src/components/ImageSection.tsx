import { useRef, useCallback } from "react";
import { Button, Tooltip } from "@heroui/react";
import { gsap } from "gsap";
import { FileImage, X } from "lucide-react";
import ImageUploader from "./ImageUploader";
import { formatFileSize, truncateSha, type ImageFileInfo } from "../utils/fileInfo";

interface ImageSectionProps {
  file: File | null;
  previewUrl: string;
  fileInfo: ImageFileInfo | null;
  onFileSelect: (file: File, url: string) => void;
  onClear: () => void;
}

export default function ImageSection({ file: _file, previewUrl, fileInfo, onFileSelect, onClear }: ImageSectionProps) {
  const infoRef = useRef<HTMLDivElement>(null);

  const handleImageSelect = useCallback(
    (selectedFile: File, url: string) => {
      onFileSelect(selectedFile, url);
      if (infoRef.current) {
        gsap.fromTo(
          infoRef.current,
          { opacity: 0, y: 8 },
          { opacity: 1, y: 0, duration: 0.35, ease: "power2.out", delay: 0.1 }
        );
      }
    },
    [onFileSelect]
  );

  return (
    <>
      {/* Upload / Preview */}
      {previewUrl ? (
        <div className="relative shrink-0 overflow-hidden rounded-lg" style={{ border: "1px solid var(--border)" }}>
          <img src={previewUrl} alt="预览" className="h-20 w-full object-contain" draggable={false} />
          <Button
            size="sm"
            variant="secondary"
            className="absolute right-1.5 top-1.5 flex h-6 w-6 min-w-0 items-center justify-center rounded p-0"
            style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--foreground)" }}
            onPress={onClear}
          >
            <X size={10} />
          </Button>
        </div>
      ) : (
        <ImageUploader onImageSelect={handleImageSelect} />
      )}

      {/* File Info */}
      {fileInfo && (
        <div
          ref={infoRef}
          className="shrink-0 rounded-lg px-3 py-2"
          style={{ background: "var(--surface-secondary)", border: "1px solid var(--border)" }}
        >
          <div className="flex items-center gap-2">
            <FileImage size={12} style={{ color: "var(--muted)", flexShrink: 0 }} />
            <span className="truncate text-xs font-medium" style={{ color: "var(--foreground)" }}>{fileInfo.name}</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px]" style={{ color: "var(--muted-secondary)" }}>
            <Tooltip delay={0}>
              <Tooltip.Trigger><span className="font-mono-nums cursor-help">{fileInfo.width} x {fileInfo.height}</span></Tooltip.Trigger>
              <Tooltip.Content showArrow><Tooltip.Arrow /><p>图片分辨率：宽度 x 高度（像素）</p></Tooltip.Content>
            </Tooltip>
            <Tooltip delay={0}>
              <Tooltip.Trigger><span className="cursor-help">{fileInfo.type}</span></Tooltip.Trigger>
              <Tooltip.Content showArrow><Tooltip.Arrow /><p>图片格式</p></Tooltip.Content>
            </Tooltip>
            <Tooltip delay={0}>
              <Tooltip.Trigger><span className="cursor-help">{formatFileSize(fileInfo.size)}</span></Tooltip.Trigger>
              <Tooltip.Content showArrow><Tooltip.Arrow /><p>文件大小</p></Tooltip.Content>
            </Tooltip>
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 text-[10px]" style={{ color: "var(--muted-secondary)" }}>
            <span className="shrink-0">SHA:</span>
            <Tooltip delay={0}>
              <Tooltip.Trigger>
                <code className="font-mono-nums cursor-pointer truncate rounded px-1 py-0.5 transition-micro hover:opacity-80" style={{ background: "var(--surface-tertiary)" }} onClick={() => navigator.clipboard.writeText(fileInfo.sha256)}>
                  {truncateSha(fileInfo.sha256)}
                </code>
              </Tooltip.Trigger>
              <Tooltip.Content showArrow><Tooltip.Arrow /><p>SHA-256 哈希值（点击复制）</p></Tooltip.Content>
            </Tooltip>
          </div>
        </div>
      )}
    </>
  );
}
