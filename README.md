# security_toolkit
# 1. Compile (requires GCC 8+ or Clang 7+ with C++17 support)
g++ -std=c++17 -Wall -Wextra -o security_toolkit security_toolkit.cpp

# 2. Run (root is required for installs, firewall, and /var/log writes)

sudo ./security_toolkit                  # interactive menu

sudo ./security_toolkit --install        # install tools only

sudo ./security_toolkit --scan /home     # scan a directory

sudo ./security_toolkit --firewall       # configure firewall

sudo ./security_toolkit --all /var       # run all three modules

sudo ./security_toolkit --help
