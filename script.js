// Arch Linux Terminal Portfolio - Shell Logic

const output = document.getElementById('output');
const commandInput = document.getElementById('command-input');
const terminal = document.getElementById('terminal');

// Page load timestamp for uptime calculation
const pageLoadTime = Date.now();

// Command history
const commandHistory = [];
let historyIndex = -1;

// Bing Bong ASCII art for neofetch
const bingBongLogo = `
       ,;;;;;;,
      ;;'    ';;
     ;;   ..   ;;
     ;   (  )   ;
     ;;   ''   ;;     
      ';;    ;;'    
   .---';    ;'---.
  /      ;;;;      \\
 ;   O          O   ;
 |                  |
 |    \\________/    |
  \\                /
   \\   |      |   /
    |  |      |  |
    |  |      |  |
   (___) (__) (___)

   * BING BONG! *
   * BING BONG! *`;

// Boot sequence with animation
function boot() {
    // Show banner first
    appendOutput('<div class="boot-banner"><img src="banner.jpg" alt="ineffective coder banner"></div>');

    const bootLines = [
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Reached target Local File Systems.</span>', delay: 100 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Started Network Manager.</span>', delay: 200 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Started OpenSSH Daemon.</span>', delay: 300 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Started D-Bus System Message Bus.</span>', delay: 400 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Listening on CUPS Scheduler.</span>', delay: 500 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Started Getty on tty1.</span>', delay: 600 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Reached target Multi-User System.</span>', delay: 700 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Started Portfolio Terminal Service.</span>', delay: 850 },
        { text: '<span class="boot-line">[  <span class="boot-ok">OK</span>  ] Reached target Graphical Interface.</span>', delay: 1000 },
        { text: '', delay: 1100 },
        { text: '<span class="boot-welcome">Welcome to <span class="user">bingbong</span> - Arch Linux (kernel 6.12.4-arch1-1)</span>', delay: 1200 },
        { text: '', delay: 1300 },
        { text: '<span class="output-info">Type <span class="dir">help</span> for available commands. Try <span class="dir">about</span> or <span class="dir">neofetch</span> to get started.</span>', delay: 1400 },
        { text: '', delay: 1500 }
    ];

    // Disable input during boot
    commandInput.disabled = true;

    bootLines.forEach(({ text, delay }) => {
        setTimeout(() => {
            appendOutput(text);
            // Enable input after last line
            if (delay === 1500) {
                commandInput.disabled = false;
                commandInput.focus();
            }
        }, delay);
    });
}

// Append output to terminal
function appendOutput(html) {
    const line = document.createElement('div');
    line.className = 'line';
    line.innerHTML = html;
    output.appendChild(line);
    scrollToBottom();
}

// Scroll to bottom of terminal
function scrollToBottom() {
    window.scrollTo(0, document.body.scrollHeight);
}

// Calculate uptime
function getUptime() {
    const elapsed = Date.now() - pageLoadTime;
    const seconds = Math.floor(elapsed / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
        return `${hours} hour${hours > 1 ? 's' : ''}, ${minutes % 60} min${minutes % 60 !== 1 ? 's' : ''}`;
    } else if (minutes > 0) {
        return `${minutes} min${minutes !== 1 ? 's' : ''}, ${seconds % 60} sec${seconds % 60 !== 1 ? 's' : ''}`;
    } else {
        return `${seconds} sec${seconds !== 1 ? 's' : ''}`;
    }
}

// Generate prompt HTML
function getPromptHTML() {
    return '<span class="output-prompt"><span class="user">ineffectivecoder</span><span class="at">@</span><span class="host">bingbong</span> <span class="path">~</span><span class="dollar">$</span></span>';
}

// Commands object
const commands = {
    help: () => {
        return `<span class="output-info">Available commands:</span>
  <span class="dir">about</span>        - Display profile card
  <span class="dir">skills</span>       - Show skills & certifications
  <span class="dir">neofetch</span>     - Display system information
  <span class="dir">projects</span>     - Fetch GitHub repositories
  <span class="dir">ls</span>           - List directory contents
  <span class="dir">cat</span> <file>   - View file contents
  <span class="dir">whoami</span>       - Display current user
  <span class="dir">uname</span> [-a]   - Print system information
  <span class="dir">uptime</span>       - Show system uptime
  <span class="dir">w</span>            - Show who is logged in
  <span class="dir">ps</span> [-ef]     - List running processes
  <span class="dir">dmesg</span>        - Print kernel ring buffer
  <span class="dir">pacman -Syu</span>  - Sync and update packages
  <span class="dir">clear</span>        - Clear terminal
  <span class="dir">help</span>         - Show this help message`;
    },

    about: () => {
        return `<div class="about-container">
    <div class="about-avatar">
        <img src="avatar.png" alt="Chris Hodson avatar">
    </div>
    <div class="about-info">
        <div class="about-name"><span class="user">Chris Hodson</span></div>
        <div class="about-handle">aka <span class="host">ineffectivecoder</span></div>
        <div class="about-title">Red Teamer & Security Researcher</div>
        <div class="about-certs"><span class="cert">OSCP</span> <span class="cert">OSCE</span> <span class="cert-expired">CRTP</span> <span class="cert-expired">CCNA</span></div>
        <div class="about-separator">━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
        <div class="about-bio">
            <p>Offensive security specialist with an IT background.</p>
            <p>Breaking Active Directory for fun and profit.</p>
            <p>Arch Linux enthusiast. Terminal dweller.</p>
        </div>
        <div class="about-links">
            <span class="dir">GitHub:</span> <a href="https://github.com/ineffectivecoder" target="_blank" rel="noopener" class="repo-name">github.com/ineffectivecoder</a>
        </div>
    </div>
</div>`;
    },

    skills: () => {
        return `<span class="skill-header">━━━━━━━━━━━━━ Skills & Expertise ━━━━━━━━━━━━━</span>

<span class="neofetch-label">Certifications:</span>
  <span class="cert">OSCP</span>  Offensive Security Certified Professional
  <span class="cert">OSCE</span>  Offensive Security Certified Expert
  <span class="cert-expired">CRTP</span>  Certified Red Team Professional <span class="output-info">(expired)</span>
  <span class="cert-expired">CCNA</span>  Cisco Certified Network Associate <span class="output-info">(expired)</span>

<span class="neofetch-label">Primary Focus:</span>
  <span class="dir">Active Directory</span> - Attacks, enumeration, exploitation
  <span class="dir">Red Team Ops</span> - Full adversary simulation
  <span class="dir">Network Pentesting</span> - Internal/external assessments

<span class="neofetch-label">Offensive Development:</span>
  <span class="dir">C/C++</span> - Shellcode loaders, malware development
  <span class="dir">Evasion</span> - DLL hijacking, sideloaders, process injection
  <span class="dir">Tradecraft</span> - AV/EDR bypass, AMSI evasion, unhooking
  <span class="dir">Reverse Engineering</span> - Binary Ninja, malware analysis

<span class="neofetch-label">Tooling:</span>
  <span class="tool-red">Cobalt Strike</span>, <span class="tool-yellow">Impacket</span>, <span class="tool-red">BloodHound</span>, <span class="tool-yellow">Rubeus</span>, <span class="tool-pink">Mimikatz</span>
  <span class="tool-orange">Burp Suite</span>, <span class="tool-cyan">Nmap</span>, <span class="tool-red">CrackMapExec</span>, <span class="tool-purple">Responder</span>

<span class="neofetch-label">Languages:</span>
  <span class="lang-python">Python</span>, <span class="lang-c">C</span>, <span class="lang-go">Go</span>, <span class="lang-bash">Bash</span>

<span class="neofetch-label">Other:</span>
  <span class="user">Windows internals</span>, <span class="host">Linux administration</span>
  <span class="dir">C2 infrastructure</span>, <span class="dir">custom implant development</span>

<span class="skill-header">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>`;
    },

    neofetch: () => {
        const uptime = getUptime();
        const logoLines = bingBongLogo.split('\n');
        const escapedLogo = logoLines.map(line =>
            line.replace(/</g, '&lt;').replace(/>/g, '&gt;')
        ).join('\n');

        return `<div class="neofetch-container">
    <div class="neofetch-logo">${escapedLogo}</div>
    <div class="neofetch-info">
        <div><span class="user">ineffectivecoder</span><span class="at">@</span><span class="host">bingbong</span></div>
        <div class="neofetch-separator">----------------------</div>
        <div><span class="neofetch-label">OS:</span> <span class="neofetch-value">Arch Linux x86_64</span></div>
        <div><span class="neofetch-label">Host:</span> <span class="neofetch-value">bingbong</span></div>
        <div><span class="neofetch-label">Kernel:</span> <span class="neofetch-value">6.12.4-arch1-1</span></div>
        <div><span class="neofetch-label">Uptime:</span> <span class="neofetch-value">${uptime}</span></div>
        <div><span class="neofetch-label">Shell:</span> <span class="neofetch-value">Portfolio ZSH 5.9</span></div>
        <div><span class="neofetch-label">Terminal:</span> <span class="neofetch-value">Web TTY</span></div>
        <div><span class="neofetch-label">Theme:</span> <span class="neofetch-value">Bing Bong Pink</span></div>
        <div class="neofetch-colors">
            <div class="neofetch-color-block" style="background: #1d2021;"></div>
            <div class="neofetch-color-block" style="background: #fb4934;"></div>
            <div class="neofetch-color-block" style="background: #e85d9a;"></div>
            <div class="neofetch-color-block" style="background: #fabd2f;"></div>
            <div class="neofetch-color-block" style="background: #1793d1;"></div>
            <div class="neofetch-color-block" style="background: #d3869b;"></div>
            <div class="neofetch-color-block" style="background: #83a598;"></div>
            <div class="neofetch-color-block" style="background: #e6e6e6;"></div>
        </div>
    </div>
</div>`;
    },

    ls: () => {
        return `<span class="dir">projects/</span>    <span class="dir">skills/</span>    <span class="file">about.txt</span>    <span class="file">contact.md</span>    <span class="file">README.md</span>`;
    },

    'pacman -Syu': () => {
        return `<span class="output-info">:: Synchronizing package databases...</span>
 core is up to date
 extra is up to date
 multilib is up to date
<span class="output-info">:: Starting full system upgrade...</span>
<span class="output-success"> there is nothing to do</span>
<span class="output-info">:: System is up to date.</span>`;
    },

    pacman: (args) => {
        if (args === '-Syu') {
            return commands['pacman -Syu']();
        }
        return `<span class="output-error">error:</span> invalid option. Try 'pacman -Syu'`;
    },

    whoami: () => {
        return 'ineffectivecoder';
    },

    dmesg: () => {
        return `<span class="output-info">[    0.000000]</span> Linux version 6.12.4-arch1-1 (linux@archlinux) (gcc 14.2.1)
<span class="output-info">[    0.000000]</span> Command line: BOOT_IMAGE=/boot/vmlinuz-linux root=UUID=a1b2c3d4 rw loglevel=3
<span class="output-info">[    0.000000]</span> BIOS-provided physical RAM map:
<span class="output-info">[    0.000000]</span> BIOS-e820: [mem 0x0000000000000000-0x000000000009ffff] usable
<span class="output-info">[    0.000000]</span> BIOS-e820: [mem 0x0000000000100000-0x00000000bfffffff] usable
<span class="output-info">[    0.000001]</span> NX (Execute Disable) protection: active
<span class="output-info">[    0.000001]</span> SMBIOS 3.0 present.
<span class="output-info">[    0.000001]</span> DMI: bingbong/bingbong, BIOS 1.0 12/26/2024
<span class="output-info">[    0.000002]</span> Hypervisor detected: KVM
<span class="output-info">[    0.004521]</span> CPU: AMD Ryzen 9 5950X 16-Core Processor
<span class="output-info">[    0.012847]</span> Memory: 32768MB available
<span class="output-info">[    0.089421]</span> cryptd: max_cpu_qlen set to 1000
<span class="output-info">[    0.124891]</span> NET: Registered PF_INET protocol family
<span class="output-info">[    0.156723]</span> audit: initializing netlink subsys (disabled)
<span class="output-info">[    0.234567]</span> systemd[1]: Detected architecture x86-64.
<span class="output-info">[    0.256891]</span> systemd[1]: Hostname set to <span class="user">&lt;bingbong&gt;</span>.
<span class="output-info">[    0.891234]</span> usb 1-1: new high-speed USB device number 2 using xhci_hcd
<span class="output-info">[    1.234567]</span> input: HID-compliant keyboard as /devices/pci0000:00
<span class="output-info">[    1.567891]</span> EXT4-fs (sda1): mounted filesystem with ordered data mode
<span class="output-info">[    2.345678]</span> systemd[1]: Started Portfolio Terminal Service.`;
    },

    ssh: (args) => {
        return `usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]
           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]
           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]
           [-i identity_file] [-J [user@]host[:port]] [-L address]
           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]
           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]
           [-w local_tun[:remote_tun]] destination [command [argument ...]]`;
    },

    nmap: (args) => {
        return `Nmap 7.94 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
PORT SPECIFICATION:
  -p <port ranges>: Only scan specified ports
  --top-ports <number>: Scan <number> most common ports
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  -sC: equivalent to --script=default
OS DETECTION:
  -O: Enable OS detection
  -A: Enable OS detection, version detection, script scanning, and traceroute
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format
  -v: Increase verbosity level (use -vv or more for greater effect)
MISC:
  -6: Enable IPv6 scanning
  -T<0-5>: Set timing template (higher is faster)

EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -sV -p 22,80,443 192.168.1.0/24
  nmap -sS -sU -T4 -A -v target`;
    },

    uname: (args) => {
        const kernel = '6.12.4-arch1-1';
        const hostname = 'bingbong';
        const arch = 'x86_64';
        const os = 'Linux';
        const date = 'Thu Dec 26 2024';

        if (args === '-a' || args === '--all') {
            return `${os} ${hostname} ${kernel} #1 SMP PREEMPT_DYNAMIC ${date} ${arch} GNU/Linux`;
        } else if (args === '-r' || args === '--kernel-release') {
            return kernel;
        } else if (args === '-s' || args === '--kernel-name') {
            return os;
        } else if (args === '-n' || args === '--nodename') {
            return hostname;
        } else if (args === '-m' || args === '--machine') {
            return arch;
        } else if (args === '-o' || args === '--operating-system') {
            return 'GNU/Linux';
        } else if (args === '-v' || args === '--kernel-version') {
            return `#1 SMP PREEMPT_DYNAMIC ${date}`;
        } else if (args === '-p' || args === '--processor') {
            return arch;
        } else if (!args) {
            return os;
        }
        return `uname: invalid option -- '${args.replace('-', '')}'
Try 'uname --help' for more information.`;
    },

    w: () => {
        const now = new Date();
        const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const uptime = getUptime();
        const loginTime = new Date(pageLoadTime).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });

        return ` <span class="output-info">${time}</span> up ${uptime},  1 user,  load average: 0.42, 0.38, 0.35
<span class="neofetch-label">USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT</span>
ineffect pts/0    :0               ${loginTime}    0.00s  0.12s  0.00s w`;
    },

    uptime: () => {
        const now = new Date();
        const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const up = getUptime();

        return ` <span class="output-info">${time}</span> up ${up},  1 user,  load average: 0.42, 0.38, 0.35`;
    },

    ps: (args) => {
        if (args === '-ef' || args === 'aux' || args === '-aux') {
            const elapsed = Math.floor((Date.now() - pageLoadTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = elapsed % 60;
            const runtime = `${mins}:${secs.toString().padStart(2, '0')}`;

            return `<span class="neofetch-label">UID        PID  PPID  C STIME TTY          TIME CMD</span>
root         1     0  0 00:00 ?        00:00:01 /sbin/init
root         2     0  0 00:00 ?        00:00:00 [kthreadd]
root        11     2  0 00:00 ?        00:00:00 [rcu_sched]
root        12     2  0 00:00 ?        00:00:00 [migration/0]
root       168     1  0 00:00 ?        00:00:00 /usr/lib/systemd/systemd-journald
root       195     1  0 00:00 ?        00:00:00 /usr/lib/systemd/systemd-udevd
dbus       312     1  0 00:00 ?        00:00:00 /usr/bin/dbus-daemon --system
root       315     1  0 00:00 ?        00:00:00 /usr/bin/sshd -D
ineffec+   420   315  0 00:00 pts/0    00:00:00 -zsh
ineffec+   512   420  0 00:00 pts/0    00:00:00 node portfolio.js
ineffec+   847   420  0 00:00 pts/0    ${runtime} chromium --portfolio
ineffec+  1024   512  0 00:00 pts/0    00:00:00 ps -ef`;
        }

        // Basic ps output
        return `<span class="neofetch-label">  PID TTY          TIME CMD</span>
  420 pts/0    00:00:00 zsh
  512 pts/0    00:00:00 node
 1024 pts/0    00:00:00 ps`;
    },

    clear: () => {
        output.innerHTML = '';
        return null;
    },

    projects: async () => {
        appendOutput('<span class="output-info">Fetching repositories from GitHub...</span>');

        try {
            const response = await fetch('https://api.github.com/users/ineffectivecoder/repos?per_page=100');

            if (!response.ok) {
                throw new Error(`GitHub API returned ${response.status}`);
            }

            const repos = await response.json();

            // Sort by stars descending
            repos.sort((a, b) => b.stargazers_count - a.stargazers_count);

            if (repos.length === 0) {
                appendOutput('<span class="output-info">No public repositories found.</span>');
                return null;
            }

            appendOutput('');
            appendOutput('<span class="output-info">Public Repositories:</span>');
            appendOutput('');

            repos.forEach(repo => {
                const name = repo.full_name;
                const desc = repo.description || 'No description';
                const stars = repo.stargazers_count;
                const url = repo.html_url;

                // Truncate description if too long
                const maxDescLength = 50;
                const truncatedDesc = desc.length > maxDescLength
                    ? desc.substring(0, maxDescLength) + '...'
                    : desc;

                // Create dots for alignment
                const dotsCount = Math.max(3, 45 - name.length);
                const dots = '.'.repeat(dotsCount);

                appendOutput(`<div class="repo-item">  <a href="${url}" target="_blank" rel="noopener" class="repo-name">${name}</a> <span class="repo-dots">${dots}</span> <span class="repo-desc">[${truncatedDesc}]</span> <span class="repo-stars">(★ ${stars})</span></div>`);
            });

            appendOutput('');

        } catch (error) {
            appendOutput(`<span class="output-error">error:</span> Failed to fetch repositories: ${error.message}`);
        }

        return null;
    },

    './projects': async () => {
        return commands.projects();
    },

    cat: (args) => {
        if (!args) {
            return `<span class="output-error">cat:</span> missing file operand`;
        }

        if (args === 'about.txt') {
            return `<span class="output-info">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>
  Hi, I'm <span class="user">ineffectivecoder</span>
  
  Red Teamer with an IT background.
  Offensive security. Breaking things to make them stronger.
  Arch Linux enthusiast. Terminal dweller.
  
  Exploiting systems by day, ricing desktops by night.
<span class="output-info">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>`;
        }

        if (args === 'contact.md') {
            return `# Contact

- <span class="dir">GitHub:</span>   github.com/ineffectivecoder
- <span class="dir">Email:</span>    [redacted]
- <span class="dir">Discord:</span>  [redacted]`;
        }

        if (args === 'README.md') {
            return `# Portfolio Terminal

Welcome to my terminal portfolio.
Type <span class="dir">help</span> to see available commands.

Built with vanilla HTML, CSS, and JavaScript.
No frameworks. No bloat. Just code.`;
        }

        if (args === '/etc/passwd') {
            return `root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/bin/nologin
daemon:x:2:2:daemon:/:/usr/bin/nologin
mail:x:8:12:mail:/var/spool/mail:/usr/bin/nologin
ftp:x:14:11:ftp:/srv/ftp:/usr/bin/nologin
http:x:33:33:http:/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
dbus:x:81:81:dbus:/:/usr/bin/nologin
systemd-journal-remote:x:982:982::/:/usr/bin/nologin
systemd-network:x:981:981::/:/usr/bin/nologin
systemd-oom:x:980:980::/:/usr/bin/nologin
systemd-resolve:x:979:979::/:/usr/bin/nologin
systemd-timesync:x:978:978::/:/usr/bin/nologin
systemd-coredump:x:977:977::/:/usr/bin/nologin
bingbong:x:1000:1000:Bing Bong:/home/bingbong:/bin/zsh
ineffectivecoder:x:1001:1001:Red Teamer:/home/ineffectivecoder:/bin/zsh`;
        }

        if (args === '/etc/shadow') {
            return `<span class="output-error">cat: /etc/shadow: Permission denied</span>

<span class="output-info">Just kidding... here you go:</span>

root:$6$rounds=656000$totallyreal$nicetrybuddy:19747:0:99999:7:::
ineffectivecoder:$6$rounds=656000$L0L0L0L$youthoughtthiswasreal:19747:0:99999:7:::
bingbong:$6$rounds=656000$c0tt0n$c4ndyt34rs:19747:0:99999:7:::

<span class="output-info">( ͡° ͜ʖ ͡°) Nice try, red teamer.</span>`;
        }

        return `<span class="output-error">cat:</span> ${args}: No such file or directory`;
    },

    cd: (args) => {
        return `<span class="output-info">cd:</span> This is a single-page portfolio. Try <span class="dir">ls</span> to see available files.`;
    },

    sudo: (args) => {
        return `<span class="output-error">[sudo] password for ineffectivecoder:</span> Nice try. 😏`;
    },

    exit: () => {
        return `<span class="output-info">logout</span>
<span class="output-info">Thanks for visiting! Come back soon.</span>`;
    }
};

// Parse and execute command
async function executeCommand(input) {
    const trimmed = input.trim();

    if (!trimmed) {
        return;
    }

    // Add to history
    commandHistory.push(trimmed);
    historyIndex = commandHistory.length;

    // Display the command with prompt
    appendOutput(`${getPromptHTML()} ${trimmed}`);

    // Parse command and arguments
    const parts = trimmed.split(' ');
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1).join(' ');

    // Check for pacman -Syu as a combined command
    if (trimmed.toLowerCase() === 'pacman -syu') {
        const result = commands['pacman -Syu']();
        if (result) appendOutput(result);
        return;
    }

    // Check if command exists
    if (commands[cmd]) {
        const result = await commands[cmd](args);
        if (result !== null && result !== undefined) {
            appendOutput(result);
        }
    } else if (cmd === './projects' || trimmed === 'projects') {
        await commands.projects();
    } else {
        appendOutput(`<span class="output-error">zsh:</span> command not found: ${cmd}`);
    }
}

// Event listeners
commandInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        const input = commandInput.value;
        commandInput.value = '';
        await executeCommand(input);
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            commandInput.value = commandHistory[historyIndex];
        }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++;
            commandInput.value = commandHistory[historyIndex];
        } else {
            historyIndex = commandHistory.length;
            commandInput.value = '';
        }
    } else if (e.key === 'l' && e.ctrlKey) {
        e.preventDefault();
        commands.clear();
    }
});

// Focus input when clicking anywhere on terminal
terminal.addEventListener('click', () => {
    commandInput.focus();
});

// Keep focus on input
document.addEventListener('keydown', (e) => {
    if (e.target !== commandInput && !e.ctrlKey && !e.metaKey && !e.altKey) {
        commandInput.focus();
    }
});

// Initialize
boot();
commandInput.focus();
