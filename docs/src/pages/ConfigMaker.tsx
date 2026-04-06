import { useState, useCallback } from "react";

type KeyVersions = Record<string, string>;

const OPERATIONS = ["encrypt", "decrypt", "rotate", "verify", "sign", "proxy", "db_query"] as const;
type Operation = (typeof OPERATIONS)[number];

interface ApiKeyEntry {
  value: string;
  keys: "all" | string[];
  operations: "all" | Operation[];
}

type OutboundPortMode = "default" | "any" | "single" | "list";

interface ConfigState {
  apiKeys: ApiKeyEntry[];
  serverPort: number;
  keyNames: Record<string, KeyVersions>;
  outboundDestinations: Record<
    string,
    Array<{ host: string; path_prefix?: string; methods?: string[]; port?: number | string | number[] }>
  >;
  dbDestinations: Record<string, Array<{ host: string; port?: number; access?: "read_only" | "read_write" }>>;
}

interface OutboundDestinationRule {
  host: string;
  path_prefix: string;
  methods: string[];
  portMode: OutboundPortMode;
  portSingle: string;
  portList: string;
}

function emptyOutboundRule(): OutboundDestinationRule {
  return {
    host: "",
    path_prefix: "",
    methods: [],
    portMode: "default",
    portSingle: "",
    portList: "",
  };
}

function parseOutboundPortFromImport(portRaw: unknown): Pick<OutboundDestinationRule, "portMode" | "portSingle" | "portList"> {
  if (portRaw === undefined || portRaw === null) {
    return { portMode: "default", portSingle: "", portList: "" };
  }
  if (portRaw === "*") {
    return { portMode: "any", portSingle: "", portList: "" };
  }
  if (typeof portRaw === "number" && Number.isInteger(portRaw)) {
    return { portMode: "single", portSingle: String(portRaw), portList: "" };
  }
  if (Array.isArray(portRaw)) {
    const nums = portRaw.filter((x): x is number => typeof x === "number" && Number.isInteger(x));
    return { portMode: "list", portSingle: "", portList: nums.join(", ") };
  }
  return { portMode: "default", portSingle: "", portList: "" };
}

function generateHexKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function validateHexKey(hex: string): { valid: true } | { valid: false; error: string } {
  const trimmed = hex.trim();
  if (trimmed === "") return { valid: true };
  if (trimmed.length !== 64) return { valid: false, error: "Key must be exactly 64 hex characters" };
  if (!/^[0-9a-fA-F]+$/.test(trimmed)) return { valid: false, error: "Key must contain only hex characters (0-9, a-f)" };
  return { valid: true };
}

function buildConfig(state: ConfigState): object {
  const keys: Record<string, Record<string, string>> = {};
  for (const [name, versions] of Object.entries(state.keyNames)) {
    const filtered: Record<string, string> = {};
    for (const [ver, hex] of Object.entries(versions)) {
      if (hex.trim().length === 64 && /^[0-9a-fA-F]+$/.test(hex)) {
        filtered[ver] = hex.toLowerCase();
      }
    }
    if (Object.keys(filtered).length > 0) {
      keys[name] = filtered;
    }
  }
  const api_keys = state.apiKeys
    .filter((k) => k.value.trim() !== "")
    .map((k) => ({
      value: k.value.trim(),
      keys: k.keys,
      operations: k.operations,
    }));
  return {
    api_keys,
    server_port: state.serverPort,
    keys,
    outbound_destinations: state.outboundDestinations,
    db_destinations: state.dbDestinations,
  };
}

const defaultApiKeyEntry = (): ApiKeyEntry => ({
  value: "",
  keys: "all",
  operations: "all",
});

export default function ConfigMaker() {
  const [apiKeys, setApiKeys] = useState<ApiKeyEntry[]>([defaultApiKeyEntry()]);
  const [serverPortInput, setServerPortInput] = useState("8080");
  const [keyNames, setKeyNames] = useState<Record<string, KeyVersions>>({
    vault: { "1": "" },
  });
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyStartVersionInput, setNewKeyStartVersionInput] = useState("1");
  const [renamingKey, setRenamingKey] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [outputFormat, setOutputFormat] = useState<"json" | "base64">("json");
  const [importInput, setImportInput] = useState("");
  const [importFormat, setImportFormat] = useState<"json" | "base64">("json");
  const [importError, setImportError] = useState<string | null>(null);
  const [outboundDestinations, setOutboundDestinations] = useState<Record<string, OutboundDestinationRule[]>>({});
  const [dbDestinations, setDbDestinations] = useState<Record<string, Array<{ host: string; port: string; access: "read_only" | "read_write" }>>>({});

  const serverPortValidation = (() => {
    const trimmed = serverPortInput.trim();
    if (trimmed === "") return { valid: false as const, error: "Server port is required" };
    const n = parseInt(trimmed, 10);
    if (isNaN(n) || !Number.isInteger(Number(trimmed))) return { valid: false as const, error: "Server port must be a whole number" };
    if (n < 1 || n > 65535) return { valid: false as const, error: "Server port must be between 1 and 65535" };
    return { valid: true as const, value: n };
  })();

  const startVersionValidation = (() => {
    const trimmed = newKeyStartVersionInput.trim();
    if (trimmed === "") return { valid: false as const, error: "Start version is required" };
    const n = parseInt(trimmed, 10);
    if (isNaN(n) || !Number.isInteger(Number(trimmed))) return { valid: false as const, error: "Start version must be a positive integer" };
    if (n < 1) return { valid: false as const, error: "Start version must be at least 1" };
    return { valid: true as const, value: n };
  })();

  const updateApiKeyValue = useCallback((i: number, v: string) => {
    setApiKeys((prev) => {
      const next = [...prev];
      next[i] = { ...next[i], value: v };
      return next;
    });
  }, []);

  const updateApiKeyKeys = useCallback((i: number, keys: "all" | string[]) => {
    setApiKeys((prev) => {
      const next = [...prev];
      next[i] = { ...next[i], keys };
      return next;
    });
  }, []);

  const updateApiKeyOperations = useCallback((i: number, operations: "all" | Operation[]) => {
    setApiKeys((prev) => {
      const next = [...prev];
      next[i] = { ...next[i], operations };
      return next;
    });
  }, []);

  const addApiKey = useCallback(() => {
    setApiKeys((prev) => [...prev, defaultApiKeyEntry()]);
  }, []);

  const removeApiKey = useCallback((i: number) => {
    setApiKeys((prev) => prev.filter((_, j) => j !== i));
  }, []);

  const addKeySet = useCallback(() => {
    const name = newKeyName.trim();
    if (!name) return;
    if (!startVersionValidation.valid) return;
    setKeyNames((prev) => ({ ...prev, [name]: { [String(startVersionValidation.value)]: "" } }));
    setNewKeyName("");
  }, [newKeyName, startVersionValidation]);

  const removeKeySet = useCallback((name: string) => {
    setKeyNames((prev) => {
      const next = { ...prev };
      delete next[name];
      return next;
    });
    setOutboundDestinations((prev) => {
      const next = { ...prev };
      delete next[name];
      return next;
    });
    setDbDestinations((prev) => {
      const next = { ...prev };
      delete next[name];
      return next;
    });
  }, []);

  const startRenameKeySet = useCallback((name: string) => {
    setRenamingKey(name);
    setRenameValue(name);
  }, []);

  const confirmRenameKeySet = useCallback(() => {
    if (renamingKey === null) return;
    const newName = renameValue.trim();
    if (!newName || newName === renamingKey) {
      setRenamingKey(null);
      return;
    }
    setKeyNames((prev) => {
      if (newName in prev) return prev;
      const next: Record<string, KeyVersions> = {};
      for (const [k, v] of Object.entries(prev)) {
        next[k === renamingKey ? newName : k] = v;
      }
      return next;
    });
    setOutboundDestinations((prev) => {
      if (!(renamingKey in prev)) return prev;
      const next: Record<string, OutboundDestinationRule[]> = {};
      for (const [k, v] of Object.entries(prev)) {
        next[k === renamingKey ? newName : k] = v;
      }
      return next;
    });
    setDbDestinations((prev) => {
      if (!(renamingKey in prev)) return prev;
      const next: Record<string, Array<{ host: string; port: string; access: "read_only" | "read_write" }>> = {};
      for (const [k, v] of Object.entries(prev)) {
        next[k === renamingKey ? newName : k] = v;
      }
      return next;
    });
    setApiKeys((prev) =>
      prev.map((entry) => {
        if (entry.keys === "all" || !entry.keys.includes(renamingKey)) return entry;
        return { ...entry, keys: entry.keys.map((k) => (k === renamingKey ? newName : k)) };
      })
    );
    setRenamingKey(null);
  }, [renamingKey, renameValue]);

  const cancelRenameKeySet = useCallback(() => {
    setRenamingKey(null);
  }, []);

  const updateEncKey = useCallback(
    (keySet: string, version: string, value: string) => {
      setKeyNames((prev) => ({
        ...prev,
        [keySet]: { ...prev[keySet], [version]: value },
      }));
    },
    []
  );

  const addVersion = useCallback((keySet: string) => {
    setKeyNames((prev) => {
      const versions = prev[keySet] || {};
      const nums = Object.keys(versions)
        .map(Number)
        .filter((n) => !isNaN(n));
      const nextVer = nums.length === 0 ? 1 : Math.max(...nums) + 1;
      return { ...prev, [keySet]: { ...versions, [String(nextVer)]: "" } };
    });
  }, []);

  const removeVersion = useCallback((keySet: string, version: string) => {
    setKeyNames((prev) => {
      const versions = { ...prev[keySet] };
      delete versions[version];
      if (Object.keys(versions).length === 0) {
        const next = { ...prev };
        delete next[keySet];
        return next;
      }
      return { ...prev, [keySet]: versions };
    });
  }, []);

  const generateForVersion = useCallback((keySet: string, version: string) => {
    setKeyNames((prev) => ({
      ...prev,
      [keySet]: { ...prev[keySet], [version]: generateHexKey() },
    }));
  }, []);

  const addDestinationRule = useCallback((keySet: string) => {
    setOutboundDestinations((prev) => ({
      ...prev,
      [keySet]: [...(prev[keySet] ?? []), emptyOutboundRule()],
    }));
  }, []);

  const removeDestinationRule = useCallback((keySet: string, index: number) => {
    setOutboundDestinations((prev) => {
      const rules = (prev[keySet] ?? []).filter((_, i) => i !== index);
      if (rules.length === 0) {
        const next = { ...prev };
        delete next[keySet];
        return next;
      }
      return { ...prev, [keySet]: rules };
    });
  }, []);

  const updateDestinationRule = useCallback(
    (
      keySet: string,
      index: number,
      field: "host" | "path_prefix" | "methods" | "portMode" | "portSingle" | "portList",
      value: string | string[] | OutboundPortMode
    ) => {
      setOutboundDestinations((prev) => {
        const rules = [...(prev[keySet] ?? [])];
        const existing = rules[index] ?? emptyOutboundRule();
        rules[index] = {
          ...existing,
          [field]: value,
        };
        return { ...prev, [keySet]: rules };
      });
    },
    []
  );

  const enableDestinationPolicy = useCallback((keySet: string) => {
    setOutboundDestinations((prev) => {
      if (keySet in prev) return prev;
      return { ...prev, [keySet]: [] };
    });
  }, []);

  const disableDestinationPolicy = useCallback((keySet: string) => {
    setOutboundDestinations((prev) => {
      if (!(keySet in prev)) return prev;
      const next = { ...prev };
      delete next[keySet];
      return next;
    });
  }, []);

  const addDbDestinationRule = useCallback((keySet: string) => {
    setDbDestinations((prev) => ({
      ...prev,
      [keySet]: [...(prev[keySet] ?? []), { host: "", port: "", access: "read_write" }],
    }));
  }, []);

  const removeDbDestinationRule = useCallback((keySet: string, index: number) => {
    setDbDestinations((prev) => {
      const rules = (prev[keySet] ?? []).filter((_, i) => i !== index);
      if (rules.length === 0) {
        const next = { ...prev };
        delete next[keySet];
        return next;
      }
      return { ...prev, [keySet]: rules };
    });
  }, []);

  const updateDbDestinationRule = useCallback(
    (keySet: string, index: number, field: "host" | "port" | "access", value: string) => {
      setDbDestinations((prev) => {
        const rules = [...(prev[keySet] ?? [])];
        const existing = rules[index] ?? { host: "", port: "", access: "read_write" as const };
        rules[index] = {
          ...existing,
          [field]: value,
        } as { host: string; port: string; access: "read_only" | "read_write" };
        return { ...prev, [keySet]: rules };
      });
    },
    []
  );

  const enableDbDestinationPolicy = useCallback((keySet: string) => {
    setDbDestinations((prev) => {
      if (keySet in prev) return prev;
      return { ...prev, [keySet]: [] };
    });
  }, []);

  const disableDbDestinationPolicy = useCallback((keySet: string) => {
    setDbDestinations((prev) => {
      if (!(keySet in prev)) return prev;
      const next = { ...prev };
      delete next[keySet];
      return next;
    });
  }, []);

  const serverPort = serverPortValidation.valid ? serverPortValidation.value : 0;
  const hasValidKeys = (() => {
    for (const versions of Object.values(keyNames)) {
      for (const hex of Object.values(versions)) {
        const v = validateHexKey(hex);
        if (v.valid && hex.trim() !== "") return true;
      }
    }
    return false;
  })();
  const configValid = serverPortValidation.valid && hasValidKeys;
  const normalizedOutboundDestinations = (() => {
    const result: Record<
      string,
      Array<{ host: string; path_prefix?: string; methods?: string[]; port?: number | string | number[] }>
    > = {};
    for (const keySet of Object.keys(outboundDestinations)) {
      const rules = outboundDestinations[keySet] ?? [];
      const normalizedRules = rules
        .map((rule) => {
          const host = rule.host.trim();
          if (!host) return null;
          const pathPrefix = rule.path_prefix.trim();
          const methods = rule.methods.map((m) => m.trim().toUpperCase()).filter((m) => m.length > 0);
          let portField: { port?: number | string | number[] } = {};
          if (rule.portMode === "any") {
            portField = { port: "*" };
          } else if (rule.portMode === "single") {
            const n = parseInt(rule.portSingle.trim(), 10);
            if (Number.isInteger(n) && n >= 1 && n <= 65535) {
              portField = { port: n };
            }
          } else if (rule.portMode === "list") {
            const parts = rule.portList
              .split(",")
              .map((s) => s.trim())
              .filter((s) => s.length > 0);
            const nums: number[] = [];
            for (const p of parts) {
              const n = parseInt(p, 10);
              if (Number.isInteger(n) && n >= 1 && n <= 65535) {
                nums.push(n);
              }
            }
            if (nums.length > 0) {
              portField = { port: nums };
            }
          }
          return {
            host,
            ...portField,
            ...(pathPrefix ? { path_prefix: pathPrefix } : {}),
            ...(methods.length > 0 ? { methods } : {}),
          };
        })
        .filter(
          (
            rule
          ): rule is {
            host: string;
            path_prefix?: string;
            methods?: string[];
            port?: number | string | number[];
          } => rule !== null
        );
      result[keySet] = normalizedRules;
    }
    return result;
  })();
  const normalizedDbDestinations = (() => {
    const result: Record<string, Array<{ host: string; port?: number; access?: "read_only" | "read_write" }>> = {};
    for (const keySet of Object.keys(dbDestinations)) {
      const rules = dbDestinations[keySet] ?? [];
      const normalizedRules: Array<{ host: string; port?: number; access?: "read_only" | "read_write" }> = [];
      for (const rule of rules) {
        const host = rule.host.trim();
        if (!host) continue;
        const parsedPort = rule.port.trim() === "" ? null : Number.parseInt(rule.port.trim(), 10);
        if (parsedPort !== null && (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535)) {
          continue;
        }
        const normalizedRule: { host: string; port?: number; access?: "read_only" | "read_write" } = {
          host,
        };
        if (parsedPort !== null) {
          normalizedRule.port = parsedPort;
        }
        if (rule.access === "read_only") {
          normalizedRule.access = "read_only";
        }
        normalizedRules.push(normalizedRule);
      }
      result[keySet] = normalizedRules;
    }
    return result;
  })();
  const config = configValid
    ? buildConfig({
        apiKeys,
        serverPort,
        keyNames,
        outboundDestinations: normalizedOutboundDestinations,
        dbDestinations: normalizedDbDestinations,
      })
    : null;
  const jsonStr = config !== null ? JSON.stringify(config, null, 2) : "";
  const base64Str =
    config !== null && typeof btoa !== "undefined"
      ? (() => {
          const bytes = new TextEncoder().encode(jsonStr);
          let binary = "";
          for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary);
        })()
      : "";

  const output = configValid ? (outputFormat === "base64" ? base64Str : jsonStr) : "";

  const copyToClipboard = useCallback(async () => {
    await navigator.clipboard.writeText(output);
  }, [output]);

  const importConfig = useCallback(() => {
    setImportError(null);
    let jsonStr: string;
    try {
      if (importFormat === "base64") {
        const binary = atob(importInput.trim());
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        jsonStr = new TextDecoder().decode(bytes);
      } else {
        jsonStr = importInput.trim();
      }
      const parsed = JSON.parse(jsonStr) as unknown;
      if (typeof parsed !== "object" || parsed === null) {
        throw new Error("Config must be a JSON object");
      }
      const obj = parsed as Record<string, unknown>;

      const apiKeysArr = obj.api_keys;
      if (!Array.isArray(apiKeysArr)) {
        throw new Error("api_keys must be an array");
      }
      const keys: ApiKeyEntry[] = apiKeysArr.map((item): ApiKeyEntry => {
        if (typeof item === "string") {
          return { value: item, keys: "all", operations: "all" };
        }
        if (typeof item === "object" && item !== null && "value" in item) {
          const o = item as Record<string, unknown>;
          const value = typeof o.value === "string" ? o.value : "";
          const keysVal = o.keys;
          const keysNorm: "all" | string[] =
            keysVal === "all" || keysVal === undefined
              ? "all"
              : Array.isArray(keysVal) && keysVal.every((x) => typeof x === "string")
                ? keysVal as string[]
                : "all";
          const opsVal = o.operations;
          const opsNorm: "all" | Operation[] =
            opsVal === "all" || opsVal === undefined
              ? "all"
              : Array.isArray(opsVal) && opsVal.every((x) => typeof x === "string" && OPERATIONS.includes(x as Operation))
                ? (opsVal as Operation[])
                : "all";
          return { value, keys: keysNorm, operations: opsNorm };
        }
        return defaultApiKeyEntry();
      });

      const serverPortVal = obj.server_port;
      const port =
        typeof serverPortVal === "number" && serverPortVal >= 1 && serverPortVal <= 65535
          ? serverPortVal
          : 8080;

      const keysObj = obj.keys;
      if (typeof keysObj !== "object" || keysObj === null) {
        throw new Error("keys must be an object");
      }
      const keyNames: Record<string, KeyVersions> = {};
      for (const [name, versions] of Object.entries(keysObj)) {
        if (typeof versions !== "object" || versions === null) continue;
        const vers: KeyVersions = {};
        for (const [ver, hex] of Object.entries(versions)) {
          if (typeof hex === "string" && hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex)) {
            vers[ver] = hex;
          }
        }
        if (Object.keys(vers).length > 0) {
          keyNames[name] = vers;
        }
      }

      setApiKeys(keys.length > 0 ? keys : [defaultApiKeyEntry()]);
      setServerPortInput(String(port));
      setKeyNames(Object.keys(keyNames).length > 0 ? keyNames : { vault: { "1": "" } });
      const outboundDestinations = obj.outbound_destinations;
      if (typeof outboundDestinations === "object" && outboundDestinations !== null && !Array.isArray(outboundDestinations)) {
        const parsedDestinations: Record<string, OutboundDestinationRule[]> = {};
        for (const [keySet, ruleList] of Object.entries(outboundDestinations as Record<string, unknown>)) {
          if (!Array.isArray(ruleList)) continue;
          parsedDestinations[keySet] = ruleList
            .map((rule) => {
              if (typeof rule !== "object" || rule === null) return null;
              const value = rule as Record<string, unknown>;
              const host = typeof value.host === "string" ? value.host : "";
              const path_prefix = typeof value.path_prefix === "string" ? value.path_prefix : "";
              const methods = Array.isArray(value.methods)
                ? value.methods.filter((method): method is string => typeof method === "string")
                : [];
              const portParts = parseOutboundPortFromImport(value.port);
              return { host, path_prefix, methods, ...portParts };
            })
            .filter((rule): rule is OutboundDestinationRule => rule !== null);
        }
        setOutboundDestinations(parsedDestinations);
      } else {
        setOutboundDestinations({});
      }
      const dbDestinations = obj.db_destinations;
      if (typeof dbDestinations === "object" && dbDestinations !== null && !Array.isArray(dbDestinations)) {
        const parsedDestinations: Record<string, Array<{ host: string; port: string; access: "read_only" | "read_write" }>> = {};
        for (const [keySet, ruleList] of Object.entries(dbDestinations as Record<string, unknown>)) {
          if (!Array.isArray(ruleList)) continue;
          parsedDestinations[keySet] = ruleList
            .map((rule) => {
              if (typeof rule !== "object" || rule === null) return null;
              const value = rule as Record<string, unknown>;
              const host = typeof value.host === "string" ? value.host : "";
              const port = typeof value.port === "number" ? String(value.port) : "";
              const access = value.access === "read_only" ? "read_only" : "read_write";
              return { host, port, access };
            })
            .filter((rule): rule is { host: string; port: string; access: "read_only" | "read_write" } => rule !== null);
        }
        setDbDestinations(parsedDestinations);
      } else {
        setDbDestinations({});
      }
      setImportInput("");
      setImportError(null);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Invalid config");
    }
  }, [importInput, importFormat]);

  return (
    <article className="max-w-none">
      <h1 className="text-3xl font-bold mb-2">Config Maker</h1>
      <p className="text-[var(--text-muted)] mb-8">
        Build your SimpleVault config interactively. Import existing configs to edit, or export as JSON or Base64.
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          Import
        </h2>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          Paste a saved config (JSON or Base64) to load and edit it.
        </p>
        <div className="flex gap-4 mb-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="import-format"
              checked={importFormat === "json"}
              onChange={() => setImportFormat("json")}
              className="accent-[var(--accent)]"
            />
            <span>JSON</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="import-format"
              checked={importFormat === "base64"}
              onChange={() => setImportFormat("base64")}
              className="accent-[var(--accent)]"
            />
            <span>Base64</span>
          </label>
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <textarea
            value={importInput}
            onChange={(e) => {
              setImportInput(e.target.value);
              setImportError(null);
            }}
            placeholder={importFormat === "base64" ? "Paste Base64-encoded config..." : 'Paste JSON config (e.g. {"api_keys":[{"value":"","keys":"all","operations":"all"}],"server_port":8080,"keys":{}})'}
            rows={4}
            className="flex-1 min-w-0 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg px-4 py-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] resize-y"
          />
          <button
            type="button"
            onClick={importConfig}
            disabled={!importInput.trim()}
            className="px-4 py-2 rounded-lg bg-[var(--accent)] text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed hover:bg-[var(--accent-muted)] transition-colors shrink-0 self-start"
          >
            Import
          </button>
        </div>
        {importError && (
          <p className="mt-2 text-sm text-red-400">
            {importError}
          </p>
        )}
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          API Keys
        </h2>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          Leave value empty for no authentication. Each key can be restricted to specific key sets and operations (encrypt, decrypt, rotate, verify, sign, proxy).
        </p>
        <div className="space-y-6">
          {apiKeys.map((entry, i) => (
            <div
              key={i}
              className="border border-[var(--border)] rounded-lg p-4 bg-[var(--surface-elevated)] space-y-3"
            >
              <div className="flex gap-2 items-center">
                <input
                  type="text"
                  value={entry.value}
                  onChange={(e) => updateApiKeyValue(i, e.target.value)}
                  placeholder="API key value (secret)"
                  className="flex-1 bg-black/30 border border-[var(--border)] rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                />
                <button
                  type="button"
                  onClick={() => removeApiKey(i)}
                  className="px-3 py-2 rounded-lg text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors shrink-0"
                  aria-label="Remove key"
                >
                  ×
                </button>
              </div>
              <div className="flex flex-wrap gap-4 items-start">
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-[var(--text-muted)] uppercase tracking-wide">Keys</span>
                  <div className="flex flex-wrap gap-2 items-center">
                    <label className="flex items-center gap-1.5 cursor-pointer text-sm">
                      <input
                        type="radio"
                        name={`keys-${i}`}
                        checked={entry.keys === "all"}
                        onChange={() => updateApiKeyKeys(i, "all")}
                        className="accent-[var(--accent)]"
                      />
                      All
                    </label>
                    {Object.keys(keyNames).length > 0 && (
                      <>
                        <label className="flex items-center gap-1.5 cursor-pointer text-sm">
                          <input
                            type="radio"
                            name={`keys-${i}`}
                            checked={entry.keys !== "all"}
                            onChange={() => updateApiKeyKeys(i, [])}
                            className="accent-[var(--accent)]"
                          />
                          Specific:
                        </label>
                        {Object.keys(keyNames).map((name) => {
                          const list = entry.keys === "all" ? [] : entry.keys;
                          const checked = list.includes(name);
                          return (
                            <label key={name} className="flex items-center gap-1.5 cursor-pointer text-sm">
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => {
                                  if (entry.keys === "all") {
                                    updateApiKeyKeys(i, [name]);
                                  } else {
                                    const next = checked ? list.filter((x) => x !== name) : [...list, name];
                                    updateApiKeyKeys(i, next.length > 0 ? next : "all");
                                  }
                                }}
                                className="accent-[var(--accent)] rounded"
                              />
                              <span className="font-mono">{name}</span>
                            </label>
                          );
                        })}
                      </>
                    )}
                  </div>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-[var(--text-muted)] uppercase tracking-wide">Operations</span>
                  <div className="flex flex-wrap gap-2 items-center">
                    <label className="flex items-center gap-1.5 cursor-pointer text-sm">
                      <input
                        type="radio"
                        name={`ops-${i}`}
                        checked={entry.operations === "all"}
                        onChange={() => updateApiKeyOperations(i, "all")}
                        className="accent-[var(--accent)]"
                      />
                      All
                    </label>
                    {OPERATIONS.map((op) => {
                      const list = entry.operations === "all" ? [] : entry.operations;
                      const checked = list.includes(op);
                      return (
                        <label key={op} className="flex items-center gap-1.5 cursor-pointer text-sm capitalize">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => {
                              if (entry.operations === "all") {
                                updateApiKeyOperations(i, [op]);
                              } else {
                                const next = checked ? list.filter((x) => x !== op) : [...list, op];
                                updateApiKeyOperations(i, next.length > 0 ? next : "all");
                              }
                            }}
                            className="accent-[var(--accent)] rounded"
                          />
                          {op}
                        </label>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          ))}
          <button
            type="button"
            onClick={addApiKey}
            className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
          >
            + Add API key
          </button>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          Server Port
        </h2>
        <input
          type="text"
          inputMode="numeric"
          value={serverPortInput}
          onChange={(e) => setServerPortInput(e.target.value)}
          placeholder="8080"
          className={`w-32 bg-[var(--surface-elevated)] border rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] ${
            !serverPortValidation.valid ? "border-red-500 focus:ring-red-500" : "border-[var(--border)]"
          }`}
        />
        {!serverPortValidation.valid && (
          <p className="mt-2 text-sm text-red-400">{serverPortValidation.error}</p>
        )}
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          Outbound Destination Policy
        </h2>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          Configure per-key-set allow rules for <code className="bg-black/30 px-1 rounded">proxy-substitute</code>. Each rule
          requires a host and can optionally restrict path prefix, methods, and destination port (default: HTTPS 443 / HTTP 80
          only; use &quot;any&quot; for arbitrary ports such as local test servers).
        </p>
        <div className="space-y-4">
          {Object.keys(keyNames).length === 0 && (
            <p className="text-sm text-[var(--text-muted)]">Add at least one key set first.</p>
          )}
          {Object.keys(keyNames).map((keySet) => {
            const policyConfigured = keySet in outboundDestinations;
            const rules = outboundDestinations[keySet] ?? [];
            return (
              <div
                key={keySet}
                className="border border-[var(--border)] rounded-lg p-4 bg-[var(--surface-elevated)] space-y-3"
              >
                <div className="flex items-center justify-between">
                  <h3 className="font-mono font-semibold text-[var(--accent)]">{keySet}</h3>
                  {policyConfigured ? (
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        onClick={() => addDestinationRule(keySet)}
                        className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
                      >
                        + Add rule
                      </button>
                      <button
                        type="button"
                        onClick={() => disableDestinationPolicy(keySet)}
                        className="text-sm text-[var(--text-muted)] hover:text-red-400"
                      >
                        Disable policy
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => enableDestinationPolicy(keySet)}
                      className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
                    >
                      Configure policy
                    </button>
                  )}
                </div>
                {!policyConfigured ? (
                  <p className="text-sm text-[var(--text-muted)]">
                    No policy configured. Destinations are allowed by default for this key set.
                  </p>
                ) : rules.length === 0 ? (
                  <p className="text-sm text-[var(--text-muted)]">
                    No rules configured. This key set will not be allowed to proxy to any destination.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {rules.map((rule, idx) => {
                      const methodList = ["GET", "POST", "PUT", "PATCH", "DELETE"];
                      return (
                        <div key={`${keySet}-${idx}`} className="border border-[var(--border)] rounded-lg p-3 space-y-3">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <input
                              type="text"
                              value={rule.host}
                              onChange={(e) => updateDestinationRule(keySet, idx, "host", e.target.value)}
                              placeholder="Host (e.g. api.stripe.com)"
                              className="bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                            />
                            <input
                              type="text"
                              value={rule.path_prefix}
                              onChange={(e) => updateDestinationRule(keySet, idx, "path_prefix", e.target.value)}
                              placeholder="Path prefix (optional, e.g. /v1/)"
                              className="bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                            />
                          </div>
                          <div className="space-y-2">
                            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wide">Port</span>
                            <select
                              value={rule.portMode}
                              onChange={(e) =>
                                updateDestinationRule(keySet, idx, "portMode", e.target.value as OutboundPortMode)
                              }
                              className="w-full md:max-w-md bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                            >
                              <option value="default">Default (443 HTTPS / 80 HTTP only)</option>
                              <option value="any">Any port (*)</option>
                              <option value="single">Single port</option>
                              <option value="list">Port list</option>
                            </select>
                            {rule.portMode === "single" && (
                              <input
                                type="text"
                                inputMode="numeric"
                                value={rule.portSingle}
                                onChange={(e) => updateDestinationRule(keySet, idx, "portSingle", e.target.value)}
                                placeholder="e.g. 8443"
                                className="w-full md:max-w-xs bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                              />
                            )}
                            {rule.portMode === "list" && (
                              <input
                                type="text"
                                value={rule.portList}
                                onChange={(e) => updateDestinationRule(keySet, idx, "portList", e.target.value)}
                                placeholder="Comma-separated, e.g. 443, 8443, 9000"
                                className="w-full bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                              />
                            )}
                          </div>
                          <div className="flex flex-wrap gap-3 items-center">
                            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wide">Methods</span>
                            {methodList.map((method) => {
                              const checked = rule.methods.includes(method);
                              return (
                                <label key={method} className="flex items-center gap-1.5 cursor-pointer text-sm">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => {
                                      const next = checked
                                        ? rule.methods.filter((m) => m !== method)
                                        : [...rule.methods, method];
                                      updateDestinationRule(keySet, idx, "methods", next);
                                    }}
                                    className="accent-[var(--accent)] rounded"
                                  />
                                  {method}
                                </label>
                              );
                            })}
                          </div>
                          <div className="flex justify-end">
                            <button
                              type="button"
                              onClick={() => removeDestinationRule(keySet, idx)}
                              className="text-sm text-[var(--text-muted)] hover:text-red-400"
                            >
                              Remove rule
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          DB Destination Policy
        </h2>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          Optional per-key-set host/port allow rules for <code className="bg-black/30 px-1 rounded">db-query</code>.
          If policy is not configured for a key set, DB destinations are allowed by default. Each rule can also set
          access mode: <code className="bg-black/30 px-1 rounded">read_only</code> or <code className="bg-black/30 px-1 rounded">read_write</code>.
        </p>
        <div className="space-y-4">
          {Object.keys(keyNames).length === 0 && (
            <p className="text-sm text-[var(--text-muted)]">Add at least one key set first.</p>
          )}
          {Object.keys(keyNames).map((keySet) => {
            const policyConfigured = keySet in dbDestinations;
            const rules = dbDestinations[keySet] ?? [];
            return (
              <div
                key={`db-${keySet}`}
                className="border border-[var(--border)] rounded-lg p-4 bg-[var(--surface-elevated)] space-y-3"
              >
                <div className="flex items-center justify-between">
                  <h3 className="font-mono font-semibold text-[var(--accent)]">{keySet}</h3>
                  {policyConfigured ? (
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        onClick={() => addDbDestinationRule(keySet)}
                        className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
                      >
                        + Add rule
                      </button>
                      <button
                        type="button"
                        onClick={() => disableDbDestinationPolicy(keySet)}
                        className="text-sm text-[var(--text-muted)] hover:text-red-400"
                      >
                        Disable policy
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => enableDbDestinationPolicy(keySet)}
                      className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
                    >
                      Configure policy
                    </button>
                  )}
                </div>
                {!policyConfigured ? (
                  <p className="text-sm text-[var(--text-muted)]">
                    No policy configured. Destinations are allowed by default for this key set.
                  </p>
                ) : rules.length === 0 ? (
                  <p className="text-sm text-[var(--text-muted)]">
                    No rules configured. This key set will not be allowed to run DB queries.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {rules.map((rule, idx) => (
                      <div key={`db-rule-${keySet}-${idx}`} className="border border-[var(--border)] rounded-lg p-3 space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                          <input
                            type="text"
                            value={rule.host}
                            onChange={(e) => updateDbDestinationRule(keySet, idx, "host", e.target.value)}
                            placeholder="Host (e.g. db.internal)"
                            className="bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                          />
                          <input
                            type="text"
                            value={rule.port}
                            onChange={(e) => updateDbDestinationRule(keySet, idx, "port", e.target.value)}
                            placeholder="Port (optional, default any)"
                            className="bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                          />
                          <select
                            value={rule.access}
                            onChange={(e) => updateDbDestinationRule(keySet, idx, "access", e.target.value)}
                            className="bg-black/30 border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                          >
                            <option value="read_write">read_write</option>
                            <option value="read_only">read_only</option>
                          </select>
                        </div>
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={() => removeDbDestinationRule(keySet, idx)}
                            className="text-sm text-[var(--text-muted)] hover:text-red-400"
                          >
                            Remove rule
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          Encryption Keys
        </h2>
        <p className="text-[var(--text-muted)] text-sm mb-2">
          Each key set (e.g. <code className="bg-black/30 px-1 rounded">vault</code>) can have multiple versions. Keys must be 64 hex characters.
        </p>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          Version numbers don&apos;t need to be sequential. Older keys can be deprecated and removed from the config over time; only keep the versions you still need for decryption.
        </p>

        <div className="flex flex-col gap-3 mb-6">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addKeySet()}
              placeholder="Key set name (e.g. vault)"
              className="flex-1 min-w-0 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            />
            <div className="flex flex-col gap-1 shrink-0">
              <div className="flex items-center gap-2">
                <label htmlFor="start-ver" className="text-sm text-[var(--text-muted)] whitespace-nowrap">
                  Start version:
                </label>
                <input
                  id="start-ver"
                  type="text"
                  inputMode="numeric"
                  value={newKeyStartVersionInput}
                  onChange={(e) => setNewKeyStartVersionInput(e.target.value)}
                  placeholder="1"
                  className={`w-20 bg-[var(--surface-elevated)] border rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] ${
                    !startVersionValidation.valid ? "border-red-500 focus:ring-red-500" : "border-[var(--border)]"
                  }`}
                />
              </div>
              {!startVersionValidation.valid && (
                <p className="text-sm text-red-400">{startVersionValidation.error}</p>
              )}
            </div>
            <button
              type="button"
              onClick={addKeySet}
              disabled={!newKeyName.trim() || !startVersionValidation.valid}
              className="px-4 py-2 rounded-lg bg-[var(--accent)] text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed hover:bg-[var(--accent-muted)] transition-colors shrink-0"
            >
              Add key set
            </button>
          </div>
        </div>

        <div className="space-y-6">
          {Object.entries(keyNames).map(([name, versions]) => (
            <div
              key={name}
              className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]"
            >
              <div className="flex items-center justify-between mb-4">
                {renamingKey === name ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") confirmRenameKeySet();
                        if (e.key === "Escape") cancelRenameKeySet();
                      }}
                      autoFocus
                      className={`w-48 bg-black/30 border rounded px-3 py-1 font-mono text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-[var(--accent)] ${
                        renameValue.trim() && renameValue.trim() !== name && renameValue.trim() in keyNames
                          ? "border-red-500 focus:ring-red-500"
                          : "border-[var(--border)]"
                      }`}
                    />
                    <button
                      type="button"
                      onClick={confirmRenameKeySet}
                      disabled={!renameValue.trim() || (renameValue.trim() !== name && renameValue.trim() in keyNames)}
                      className="px-2 py-1 rounded text-sm text-green-400 hover:text-green-300 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      onClick={cancelRenameKeySet}
                      className="px-2 py-1 rounded text-sm text-[var(--text-muted)] hover:text-[var(--text)]"
                    >
                      Cancel
                    </button>
                    {renameValue.trim() && renameValue.trim() !== name && renameValue.trim() in keyNames && (
                      <span className="text-sm text-red-400">Name already exists</span>
                    )}
                  </div>
                ) : (
                  <h3 className="font-mono font-semibold text-[var(--accent)]">
                    {name}
                  </h3>
                )}
                <div className="flex items-center gap-2">
                  {renamingKey !== name && (
                    <button
                      type="button"
                      onClick={() => startRenameKeySet(name)}
                      className="text-sm text-[var(--text-muted)] hover:text-[var(--accent)]"
                    >
                      Rename
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => removeKeySet(name)}
                    className="text-sm text-[var(--text-muted)] hover:text-red-400"
                  >
                    Remove
                  </button>
                </div>
              </div>
              <div className="space-y-3">
                {Object.entries(versions).map(([ver, hex]) => {
                  const hexValidation = validateHexKey(hex);
                  return (
                  <div key={ver} className="flex flex-col gap-1">
                    <div className="flex flex-wrap gap-2 items-center">
                      <span className="w-8 shrink-0 font-mono text-[var(--text-muted)]">
                        v{ver}
                      </span>
                      <input
                        type="text"
                        value={hex}
                        onChange={(e) =>
                          updateEncKey(name, ver, e.target.value)
                        }
                        placeholder="64 hex chars"
                        className={`flex-1 min-w-0 bg-black/30 border rounded px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] ${
                          !hexValidation.valid && hex.trim() !== ""
                            ? "border-red-500 focus:ring-red-500"
                            : "border-[var(--border)]"
                        }`}
                      />
                      <div className="flex shrink-0 gap-1">
                      <button
                        type="button"
                        onClick={() => generateForVersion(name, ver)}
                        className="px-3 py-2 rounded text-sm bg-[var(--accent)]/20 text-[var(--accent)] hover:bg-[var(--accent)]/30"
                      >
                        Generate
                      </button>
                      {Object.keys(versions).length > 1 && (
                        <button
                          type="button"
                          onClick={() => removeVersion(name, ver)}
                          className="px-2 py-1 rounded text-[var(--text-muted)] hover:text-red-400"
                          aria-label="Remove version"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  </div>
                  {!hexValidation.valid && hex.trim() !== "" && (
                    <p className="text-sm text-red-400 pl-10">{hexValidation.error}</p>
                  )}
                </div>
                  );
                })}
                <button
                  type="button"
                  onClick={() => addVersion(name)}
                  className="text-sm text-[var(--accent)] hover:text-[var(--accent-muted)]"
                >
                  + Add version
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">
          Export
        </h2>
        <div className="flex gap-4 mb-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="format"
              checked={outputFormat === "json"}
              onChange={() => setOutputFormat("json")}
              className="accent-[var(--accent)]"
            />
            <span>JSON</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="format"
              checked={outputFormat === "base64"}
              onChange={() => setOutputFormat("base64")}
              className="accent-[var(--accent)]"
            />
            <span>Base64</span>
          </label>
        </div>
        <p className="text-[var(--text-muted)] text-sm mb-4">
          {outputFormat === "base64"
            ? "Base64-encoded config for env vars, secrets, or compact storage."
            : "Pretty-printed JSON config file."}
        </p>
        <div className="relative min-w-0">
          {!configValid ? (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm space-y-1">
              {!serverPortValidation.valid && <p>{serverPortValidation.error}</p>}
              {serverPortValidation.valid && !hasValidKeys && (
                <p>At least one valid encryption key (64 hex characters) is required.</p>
              )}
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {output && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={copyToClipboard}
                    className="px-3 py-1.5 rounded text-sm bg-[var(--accent)]/20 text-[var(--accent)] hover:bg-[var(--accent)]/30"
                  >
                    Copy
                  </button>
                </div>
              )}
              <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono max-h-80 overflow-y-auto">
                {output || "Add at least one encryption key to generate config."}
              </pre>
            </div>
          )}
        </div>
      </section>
    </article>
  );
}
