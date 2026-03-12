type JsonPathResolution = {
  found: boolean;
  value?: unknown;
};

export function resolveJsonPath(root: unknown, path: string): JsonPathResolution {
  if (path === "$") {
    return {
      found: true,
      value: root,
    };
  }

  if (!path.startsWith("$")) {
    return { found: false };
  }

  let current = root;
  let cursor = 1;

  while (cursor < path.length) {
    const token = path[cursor];

    if (token === ".") {
      cursor += 1;
      const start = cursor;

      while (cursor < path.length && /[A-Za-z0-9_]/.test(path[cursor])) {
        cursor += 1;
      }

      const key = path.slice(start, cursor);
      if (key.length === 0 || !hasProperty(current, key)) {
        return { found: false };
      }

      current = current[key];
      continue;
    }

    if (token === "[") {
      cursor += 1;
      const start = cursor;

      while (cursor < path.length && /[0-9]/.test(path[cursor])) {
        cursor += 1;
      }

      if (path[cursor] !== "]") {
        return { found: false };
      }

      const index = Number(path.slice(start, cursor));
      cursor += 1;

      if (!Array.isArray(current) || Number.isNaN(index) || index < 0 || index >= current.length) {
        return { found: false };
      }

      current = current[index];
      continue;
    }

    return { found: false };
  }

  return {
    found: true,
    value: current,
  };
}

function hasProperty(
  value: unknown,
  key: string,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.prototype.hasOwnProperty.call(value, key)
  );
}
