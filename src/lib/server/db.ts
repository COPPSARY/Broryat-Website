import "dotenv/config";
import postgres from "postgres";

let client: postgres.Sql | undefined;

export function hasDatabaseUrl() {
  return Boolean(process.env.DATABASE_URL);
}

export function db() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not configured.");
  }

  client ??= postgres(process.env.DATABASE_URL, {
    max: 5,
    idle_timeout: 20,
    connect_timeout: 10,
    ssl: "require",
    prepare: false,
  });

  return client;
}

const tableExistsCache = new Map<string, Promise<boolean>>();

export async function tableExists(tableName: string) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(tableName) || !hasDatabaseUrl()) {
    return false;
  }

  let cached = tableExistsCache.get(tableName);
  if (!cached) {
    cached = db()<{ exists: boolean }[]>`
      select to_regclass(${`public.${tableName}`}) is not null as exists
    `.then((rows) => rows[0]?.exists ?? false);
    tableExistsCache.set(tableName, cached);
  }

  return cached;
}
