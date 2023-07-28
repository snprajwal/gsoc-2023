# Google Summer of Code 2023

**Project page**: [Forensic analysis of container checkpoints](https://summerofcode.withgoogle.com/archive/2023/projects/9Qr4FVa7)
<br>
**Organisation**: [CRIU](https://criu.org)
<br>
**Mentors**: [Radostin Stoyanov](https://github.com/rst0git), [Adrian Reber](https://github.com/areber)
<br>
**Proposal**: [Prajwal S N - CRIU (GSoC 2023)](/Prajwal%20S%20N%20-%20CRIU%20%28GSoC%202023%29.pdf)

# Overview

The [crit](https://github.com/checkpoint-restore/go-criu/tree/master/crit) library in go-criu was created during GSoC 2022 to enable analysis of CRIU images with tools written in Go. It allows container management tools such as checkpointctl and Podman to provide capabilities similar to CRIT. The goal of this project is to extend this library with functionality for forensic analysis of container checkpoints to provide a better user experience. To effectively utilise this new feature, the checkpointctl CLI tool would also be extended to display information about the processes included in a container checkpoint and their runtime state (e.g. memory state, open files, sockets, etc).

# Pull requests

- [`go-criu#109` crit: fix proto imports for library](https://github.com/checkpoint-restore/go-criu/pull/109)
- [`checkpointctl#56` feat: add flag to view process tree](https://github.com/checkpoint-restore/checkpointctl/pull/56)
- [`checkpointctl#74` feat: display file descriptors](https://github.com/checkpoint-restore/checkpointctl/pull/74)
- [`go-criu#138` feat(crit): add `crit x sk` for sockets](https://github.com/checkpoint-restore/go-criu/pull/138)
- [`checkpointctl#87` feat: filter by PID in process tree](https://github.com/checkpoint-restore/checkpointctl/pull/87)
- [`checkpointctl#94` feat: display sockets in process tree](https://github.com/checkpoint-restore/checkpointctl/pull/94)

# Acknowledgements

I would like to thank my mentors Radostin and Adrian for their encouragement, perspectives, and constant support. This time, apart from becoming a better developer, the experience also taught me about the process of scaling and maintaining an open-source project in a way that enables other developers to contribute seamlessly. I extend my gratitude to the GSoC team at Google for making it possible to contribute and work with this amazing team of people from across the world.

I would also like to thank the [mdpdf](https://github.com/bluehatbrit/mdpdf) project for enabling me to conveniently generate PDFs from Markdown.
