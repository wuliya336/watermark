import { useCallback, useState } from "react";
import { Upload } from "lucide-react";

interface ImageUploaderProps {
  onImageSelect: (file: File, previewUrl: string) => void;
}

export default function ImageUploader({ onImageSelect }: ImageUploaderProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleFile = useCallback(
    (file: File) => {
      if (!file.type.startsWith("image/")) {
        alert("请上传图片文件");
        return;
      }
      const url = URL.createObjectURL(file);
      onImageSelect(file, url);
    },
    [onImageSelect]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);

      const file = e.dataTransfer.files[0];
      if (file) {
        handleFile(file);
        return;
      }

      const plain = e.dataTransfer.getData("text/plain").trim();
      if (plain) {
        const isFileUri = plain.startsWith("file:///");
        const isWindowsPath = /^[a-zA-Z]:\\/.test(plain);
        if (isFileUri || isWindowsPath) {
          alert("暂不支持直接拖拽本地文件路径，请使用点击上传或将文件拖到桌面后再拖入。");
          return;
        }
        if (/^https?:\/\//.test(plain)) {
          fetch(plain)
            .then((res) => res.blob())
            .then((blob) => {
              const name = plain.split("/").pop() || "image.png";
              const fetchedFile = new File([blob], name, { type: blob.type || "image/png" });
              const url = URL.createObjectURL(fetchedFile);
              onImageSelect(fetchedFile, url);
            })
            .catch(() => alert("无法下载拖拽的图片"));
          return;
        }
      }

      const uri = e.dataTransfer.getData("text/uri-list").trim();
      if (uri && /^https?:\/\//.test(uri)) {
        fetch(uri)
          .then((res) => res.blob())
          .then((blob) => {
            const name = uri.split("/").pop() || "image.png";
            const fetchedFile = new File([blob], name, { type: blob.type || "image/png" });
            const url = URL.createObjectURL(fetchedFile);
            onImageSelect(fetchedFile, url);
          })
          .catch(() => alert("无法下载拖拽的图片"));
        return;
      }
    },
    [handleFile, onImageSelect]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = "copy";
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className="relative overflow-hidden rounded-lg border border-dashed px-4 py-6 text-center transition-micro"
      style={{
        borderColor: isDragging ? "var(--foreground)" : "var(--border)",
        backgroundColor: isDragging ? "var(--surface-secondary)" : "transparent",
      }}
    >
      {isDragging && (
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background: "linear-gradient(90deg, transparent, rgba(128,128,128,0.05), transparent)",
            backgroundSize: "200% 100%",
            animation: "shimmer 1s linear infinite",
          }}
        />
      )}
      <input
        type="file"
        accept="image/*"
        onChange={handleChange}
        className="hidden"
        id="image-upload"
      />
      <label htmlFor="image-upload" className="relative block cursor-pointer">
        <Upload
          size={24}
          className="mx-auto mb-2"
          style={{ color: "var(--muted)" }}
        />
        <p className="text-xs" style={{ color: "var(--foreground)" }}>
          拖拽图片到此处，或{" "}
          <span className="underline underline-offset-2">点击上传</span>
        </p>
        <p className="mt-1 text-[10px]" style={{ color: "var(--muted-secondary)" }}>
          PNG / JPEG / BMP / WebP
        </p>
      </label>
    </div>
  );
}
