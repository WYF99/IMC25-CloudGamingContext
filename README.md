# Games Are Not Equal: Classifying Cloud Gaming Contexts for Effective User Experience Measurement

_Yifan Wang, Minzhao Lyu, Vijay Sivaraman_

In Proc. ACM Internet Measurement Conference (IMC), Madison, WI, USA, 2025

---
```
@inproceedings{wang_games_2025,
  author = {Wang, Yifan and Lyu, Minzhao and Sivaraman, Vijay},
  title = {{Games Are Not Equal: Classifying Cloud Gaming Contexts for Effective User Experience Measurement}},
  booktitle = {Proc. ACM Internet Measurement Conference (IMC)},
  year = {2025},
  month = oct,
  address = {Madison, WI, USA},
}
```
---

This repository contains the validation scripts for the cloud gaming dataset shared in our IMC'25 paper, as well as preprocessing code that converts the packet info in traffic traces to json format for analysis.
\
The actual data, consisting of traffic traces (pcap files) and player activity stage labels (csv files), are shared on our university cloud drive and can be accessed here: https://minzhaolyu.github.io/dataset/MultimediaNetworkTrafficDataset.

The dataset is organized as follows:
```
context/
├── pcap/
│   ├── <device_type>/
│   │   ├── <software_type>/
│   │   │   ├── <game_title>/
│   │   │   │   ├── <graphics_setting>/
│   │   │   │   │   ├── <experiment_number>/
│   │   │   │   │   │   └── <pcap_file>
│   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   └── ...
│   │   └── ...
│   └── ...
│
└── csv/
    ├── <device_type>/
    │   ├── <software_type>/
    │   │   ├── <game_title>/
    │   │   │   ├── <graphics_setting>/
    │   │   │   │   ├── <experiment_number>/
    │   │   │   │   │   └── <csv_file>
    │   │   │   │   └── ...
    │   │   │   └── ...
    │   │   └── ...
    │   └── ...
    └── ...
```

For further data enquiries, please contact the corresponding author, [Minzhao Lyu](mailto:minzhao.lyu@unsw.edu.au).
