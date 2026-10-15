# Network Traffic Analyzer
Pure-Python .pcap analyzer: protocol breakdown, packet stats, top talkers, traffic trends, basic scan detection.

    pip install matplotlib
    python analyzer.py sample sample.pcap
    python analyzer.py analyze sample.pcap

Real traffic: Wireshark/tcpdump se apne network ka capture lo (`tcpdump -w cap.pcap`), pcap format me save karo.
Sirf apna ya authorized traffic analyze karo.
