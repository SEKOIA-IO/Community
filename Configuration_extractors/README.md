# Configuration_Extractors

## Description
This repo contains various Python scripts for extracting malware configurations, especially made for AssemblyLine4 with their meta-service [ConfigExtractor](https://github.com/CybercentreCanada/assemblyline-service-configextractor)

## Usage
Natively, this repo is used by the ASL4 configuration extraction service, but it is also possible to use these scripts through CLI or in different python scripts without AL4 using [configextractor-py](https://github.com/CybercentreCanada/configextractor-py) `cx </path/to/extractor_dir> </path/to/samples>`.

## Test
To test the extractors, we used the hashes contained in the YARA rules of each extractor.

## References
- [Advent of Configuration Extraction – Part 1: Pipeline Overview – First Steps with Kaiji Configuration Unboxing](https://blog.sekoia.io/advent-of-configuration-extraction-part-1-pipeline-overview-first-steps-with-kaiji-configuration-unboxing/)
- [Advent of Configuration Extraction – Part 2: Unwrapping QuasarRAT’s Configuration](https://blog.sekoia.io/advent-of-configuration-extraction-part-2-unwrapping-quasarrats-configuration/)
- [Advent of Configuration Extraction – Part 3: Mapping GOT/PLT and Disassembling the SNOWLIGHT Loader](https://blog.sekoia.io/advent-of-configuration-extraction-part-3-mapping-got-plt-and-disassembling-the-snowlight-loader/)
