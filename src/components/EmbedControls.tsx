import { useState, useRef } from "react";
import { Button, Spinner, TextArea, Select, ListBox } from "@heroui/react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { Download } from "lucide-react";
import type { ResultData } from "../types";

interface EmbedControlsProps {
  file: File | null;
  result: ResultData | null;
  onResult: (result: ResultData) => void;
}

export default function EmbedControls({ file, result, onResult }: EmbedControlsProps) {
  const [watermarkText, setWatermarkText] = useState("");
  const [loading, setLoading] = useState(false);
  const [outputFormat, setOutputFormat] = useState("jpeg");
  const inputRef = useRef<HTMLDivElement>(null);

  const handleEmbed = async () => {
    if (!file || !watermarkText.trim()) {
      alert("请选择图片并输入水印文本");
      return;
    }
    setLoading(true);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const imageBytes = new Uint8Array(arrayBuffer);
      const response = await invoke<{
        image_bytes: number[];
        wm_size: number;
        duration_ms: number;
        mime_type: string;
      }>("embed_watermark", {
        imageBytes,
        watermarkText: watermarkText.trim(),
        format: outputFormat,
      });
      const blob = new Blob([new Uint8Array(response.image_bytes)], {
        type: response.mime_type,
      });
      const dataUrl = URL.createObjectURL(blob);
      const ext = response.mime_type === "image/jpeg" ? "jpg" : "png";
      onResult({
        type: "image",
        dataUrl,
        durationMs: response.duration_ms,
        filename: `watermarked_${file.name.replace(/\.[^/.]+$/, "")}.${ext}`,
        wmSize: response.wm_size,
        mimeType: response.mime_type,
      });
    } catch (err) {
      alert(`嵌入失败: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAs = async () => {
    if (!result || result.type !== "image") return;
    const imageResult = result as Extract<typeof result, { type: "image" }>;
    const ext = imageResult.mimeType === "image/jpeg" ? "jpg" : "png";
    const filterName = ext === "jpg" ? "JPEG Image" : "PNG Image";
    const filePath = await save({
      defaultPath: imageResult.filename.replace(/\.[^/.]+$/, `.${ext}`),
      filters: [{ name: filterName, extensions: [ext] }],
    });
    if (filePath) {
      const response = await fetch(imageResult.dataUrl);
      const blob = await response.blob();
      const buffer = await blob.arrayBuffer();
      const bytes = Array.from(new Uint8Array(buffer));
      await invoke("save_file", { path: filePath, data: bytes });
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* Watermark Input */}
      {file && (
        <div ref={inputRef}>
          <TextArea
            fullWidth
            aria-label="水印文本"
            placeholder='{"a":1715424000000,"b":"v1.0.0","c":"user123"}'
            value={watermarkText}
            onChange={(e) => setWatermarkText(e.target.value)}
            rows={2}
            variant="secondary"
          />
        </div>
      )}

      {/* Output Format */}
      {file && (
        <div className="flex flex-col gap-1">
          <span className="text-[11px] font-medium" style={{ color: "var(--muted)" }}>
            输出格式
          </span>
          <Select
            aria-label="输出格式"
            selectedKey={outputFormat}
            onSelectionChange={(key) => setOutputFormat(key as string)}
            variant="secondary"
            className="text-sm"
          >
            <Select.Trigger>
              <Select.Value />
              <Select.Indicator />
            </Select.Trigger>
            <Select.Popover>
              <ListBox>
                <ListBox.Item id="jpeg" textValue="JPEG (文件小，推荐)">
                  JPEG (文件小，推荐)
                  <ListBox.ItemIndicator />
                </ListBox.Item>
                <ListBox.Item id="png" textValue="PNG (无损)">
                  PNG (无损)
                  <ListBox.ItemIndicator />
                </ListBox.Item>
              </ListBox>
            </Select.Popover>
          </Select>
          <span className="text-[10px]" style={{ color: "var(--muted-secondary)" }}>
            JPEG 会显著减小文件体积，且水印在合理压缩质量下仍可提取
          </span>
        </div>
      )}

      {/* Action Button */}
      {file && (
        <Button
          variant="primary"
          size="sm"
          fullWidth
          onPress={handleEmbed}
          isDisabled={!file || !watermarkText.trim() || loading}
        >
          {loading ? <Spinner color="current" size="sm" /> : "嵌入水印"}
        </Button>
      )}

      {/* Save As Button */}
      {result?.type === "image" && (
        <Button variant="primary" size="sm" fullWidth onPress={handleSaveAs}>
          <Download size={14} className="mr-1" />
          另存为
        </Button>
      )}
    </div>
  );
}
