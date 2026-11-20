#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { analyzeDelegation } from "./analyzer.js";

const file = process.argv[2];
if (!file) {
  console.error("用法: node src/cli.js <snapshot.json>");
  process.exit(2);
}

const snapshot = JSON.parse(await readFile(file, "utf8"));
const result = analyzeDelegation(snapshot);
console.log(JSON.stringify(result, null, 2));
