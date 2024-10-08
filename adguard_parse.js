// Parse adguard filter

import { FilterListParser } from "@adguard/agtree";
import { writeFile, readFile } from "fs/promises";

const filterList = await readFile('filterlist.txt', 'utf-8');
const parsedFilter = FilterListParser.parse(filterList);
await writeFile("parsedfilter.json", JSON.stringify(parsedFilter));
