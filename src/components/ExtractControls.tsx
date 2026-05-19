import { useState, useCallback, useEffect } from "react";
import { Button, Spinner, Input } from "@heroui/react";
import { invoke } from "@tauri-apps/api/core";
import { Copy, Check } from "lucide-react";
import type { ResultData } from "../types";

interface ExtractControlsProps {
  file: File | null;
  result: ResultData | null;
  wmSize: number;
  onResult: (result: ResultData) => void;
}

function formatWatermarkText(text: string): string {
  try {
    const parsed = JSON.parse(text);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return text;
  }
}

export default function ExtractControls({ file, result, wmSize, onResult }: ExtractControlsProps) {
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [inputWmSize, setInputWmSize] = useState(String(wmSize || ""));

  useEffect(() => {
    setInputWmSize(String(wmSize || ""));
  }, [wmSize]);

  const handleExtract = async () => {
    if (!file) {
      alert("请选择图片");
      return;
    }
    const size = parseInt(inputWmSize, 10);
    if (!size || size <= 0) {
      alert("请输入有效的水印长度 (wm_size)");
      return;
    }
    setLoading(true);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const imageBytes = new Uint8Array(arrayBuffer);
      const response = await invoke<{
        watermark_text: string;
        duration_ms: number;
      }>("extract_watermark", {
        imageBytes,
        wmSize: size,
      });
      onResult({
        type: "text",
        text: response.watermark_text,
        durationMs: response.duration_ms,
      });
    } catch (err) {
      alert(`提取失败: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = useCallback(async () => {
    if (!result || result.type !== "text") return;
    await navigator.clipboard.writeText(formatWatermarkText(result.text));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [result]);

  const textResult = result?.type === "text" ? result : null;

  return (
    <div className="flex flex-col gap-3">
      {/* wm_size Input */}
      {file && (
        <div className="flex flex-col gap-1">
          <span className="text-[11px] font-medium" style={{ color: "var(--muted)" }}>
            水印长度 (wm_size)
          </span>
          <Input
            fullWidth
            aria-label="水印长度"
            placeholder="请输入水印比特长度"
            value={inputWmSize}
            onChange={(e) => setInputWmSize(e.target.value)}
            className="text-sm"
            variant="secondary"
            type="number"
          />
        </div>
      )}

      {/* Action Button */}
      {file && (
        <Button
          variant="secondary"
          size="sm"
          fullWidth
          onPress={handleExtract}
          isDisabled={!file || loading}
        >
          {loading ? <Spinner color="current" size="sm" /> : "提取水印"}
        </Button>
      )}

      {/* Result Display */}
      {textResult && (
        <div
          className="flex flex-col gap-2 rounded-lg px-3 py-2.5"
          style={{
            background: "var(--surface-secondary)",
            border: "1px solid var(--border)",
          }}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-medium" style={{ color: "var(--muted)" }}>
              提取结果
            </span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] transition-micro hover:opacity-80"
              style={{
                background: "var(--surface-tertiary)",
                color: copied ? "var(--success)" : "var(--foreground)",
              }}
            >
              {copied ? <Check size={10} /> : <Copy size={10} />}
              {copied ? "已复制" : "复制"}
            </button>
          </div>
          <pre
            className="max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed"
            style={{ color: "var(--foreground)" }}
          >
            {formatWatermarkText(textResult.text)}
          </pre>
          <span
            className="font-mono-nums text-[10px]"
            style={{ color: "var(--muted-secondary)" }}
          >
            耗时: {Math.round(textResult.durationMs)}ms
          </span>
        </div>
      )}
    </div>
  );
}
