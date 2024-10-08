// Regenerate adguard filter

import { FilterListParser } from "@adguard/agtree";
import { writeFile, readFile } from "fs/promises";

let parsedFilter = JSON.parse(await readFile("parsedfilter.json", "utf8"));
const filterListGenerated = FilterListParser.generate(parsedFilter);
await writeFile("filterlist.txt", filterListGenerated);
