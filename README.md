# -Developer-Vulnerability-Scanner-DVS-

 Team: <br/>
   -> Meaza Mulatu Tale </br>
   -> Mahlet Belay Mulugeta
   
 ## Developer Vulnerability Scanner (DVS)
  -> A tool for detecting security vulnerabilities in code and dependencies, offering both web-based and local scanning.

### Overview
 DVS provides two scanning methods:

  -> Web-Based Scanning: Submit a GitHub repo URL for remote scanning.

  -> Local NPM Scanner: Install an npm package to scan local projects and view results in a dashboard.

### Core Features
   ✔ Static code analysis (SQLi, XSS, etc.) <br/>
   ✔ Dependency vulnerability checks (package.json) <br/>
   ✔ CI/CD integration (GitHub Actions) <br/>
   ✔ Interactive dashboard with severity levels & fixes <br/>

### System Architecture
   -> Frontend: Vite + React (web/local dashboard) <br/>
   -> Backend: Node.js + Express/Nest.js (GitHub OAuth, scanning, DB) <br/>
   -> NPM CLI: Scans local projects, launches dashboard (dvs scan) <br/>

### Usage
  1. Log in via GitHub OAuth.
  2. Submit a repo URL.
  3. View results in the dashboard.

