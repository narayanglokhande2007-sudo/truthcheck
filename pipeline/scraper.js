// pipeline/scraper.js – 30-Source Phishing Feed Collector with Auto-Dedup
const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');

// 30 carefully selected free sources (no API key required)
const SOURCES = [
  { name: 'OpenPhish', url: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', type: 'text' },
  { name: 'PhishTank', url: 'https://data.phishtank.com/data/online-valid.json', type: 'json', urlKey: 'url' },
  { name: 'PhishStats', url: 'https://phishstats.info/phish_score.csv', type: 'csv', urlIndex: 0 },
  { name: 'URLhaus', url: 'https://urlhaus.abuse.ch/downloads/text_online/', type: 'text' },
  { name: 'ThreatFox', url: 'https://threatfox.abuse.ch/export/json/recent/', type: 'json', urlKey: 'ioc_value' },
  { name: 'Blocklist.de', url: 'https://lists.blocklist.de/lists/phishing.txt', type: 'text' },
  { name: 'Phishing Army', url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt', type: 'text' },
  { name: 'VXVault', url: 'http://vxvault.net/URL_List.php', type: 'text' },
  { name: 'MalwareURL', url: 'https://malwareurl.com/listing-urls.csv', type: 'csv', urlIndex: 0 },
  { name: 'Cert.pl', url: 'https://hole.cert.pl/domains/domains.json', type: 'json', urlKey: 'domain' },
  { name: 'CyberCrime Tracker', url: 'https://cybercrime-tracker.net/ccam.php', type: 'text' },
  { name: 'PhishFindR', url: 'https://raw.githubusercontent.com/mitchellkrogza/PhishFindR/master/input/source_phish.txt', type: 'text' },
  { name: 'ThreatConnect', url: 'https://raw.githubusercontent.com/ThreatConnect/CE_Community_Feed/main/indicators.csv', type: 'csv', urlIndex: 0 },
  { name: 'Abuse.ch URLhaus (Feed)', url: 'https://urlhaus.abuse.ch/downloads/csv_online/', type: 'csv', urlIndex: 2 },
  { name: 'Pulsedive', url: 'https://pulsedive.com/premium/?view=export&type=json', type: 'json', urlKey: 'indicator' },
  { name: 'Cisco Talos', url: 'https://www.talosintelligence.com/documents/ip-blacklist', type: 'text' },
  { name: 'Spam404', url: 'https://raw.githubusercontent.com/Spam404/lists/master/phishing.txt', type: 'text' },
  { name: 'PhishStats (Extended)', url: 'https://phishstats.info/phish_score_ext.csv', type: 'csv', urlIndex: 0 },
  { name: 'CRDF Threat Center', url: 'https://threatcenter.crdf.fr/feeds/active_phishing_urls.txt', type: 'text' },
  { name: 'URLScan.io (Public Feed)', url: 'https://raw.githubusercontent.com/urlscan/phish.gg/main/data.csv', type: 'csv', urlIndex: 0 },
  { name: 'MalSilo', url: 'https://malsilo.gitlab.io/feeds/phishing_urls.txt', type: 'text' },
  { name: 'MalwareBazaar', url: 'https://bazaar.abuse.ch/export/csv/recent/', type: 'csv', urlIndex: 1 },
  { name: 'AlienVault OTX (Public Pulse)', url: 'https://otx.alienvault.com/api/v1/indicators/export?types=url&limit=1000', type: 'json', urlKey: 'indicator' },
  { name: 'Phishing Inbox', url: 'https://raw.githubusercontent.com/xRiot45/PhishInbox/main/phish.txt', type: 'text' },
  { name: 'Cyber Threat Coalition', url: 'https://blocklist.cyberthreatcoalition.org/vetted_urls.txt', type: 'text' },
  { name: 'H3X-T Phish Feed', url: 'https://raw.githubusercontent.com/h3x-t/cybersecurity-phishing-feed/main/urls.txt', type: 'text' },
  { name: 'Phishing Database by mitchellkrogza', url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt', type: 'text' },
  { name: 'Project Honey Pot', url: 'https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1', type: 'text' },
  { name: 'PhishStats (CSV Online)', url: 'https://phishstats.info/phish_score_online.csv', type: 'csv', urlIndex: 0 },
  { name: 'StopForumSpam', url: 'https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt', type: 'text' }
];

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'VerifyPulseBot/3.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', (e) => {
      console.error(`  Network error for ${url}: ${e.message}`);
      resolve('');
    });
  });
}

function extractURLsFromCSV(csv, colIndex) {
  const lines = csv.split(/\r?\n/);
  const urls = [];
  for (let line of lines) {
    const cols = line.split(',');
    if (cols.length > colIndex) {
      const val = cols[colIndex].replace(/"/g, '').trim();
      if (val.startsWith('http')) urls.push(val);
    }
  }
  return urls;
}

async function fetchAll() {
  let allUrls = [];
  for (const source of SOURCES) {
    try {
      console.log(`Fetching ${source.name}...`);
      const raw = await fetchText(source.url);
      if (!raw) continue;
      if (source.type === 'text') {
        const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const urls = lines.filter(l => l.startsWith('http') || l.startsWith('https'));
        allUrls.push(...urls);
        console.log(`  ${urls.length} URLs from ${source.name}`);
      } else if (source.type === 'json') {
        try {
          const json = JSON.parse(raw);
          if (Array.isArray(json)) {
            for (const item of json) {
              const url = item[source.urlKey];
              if (url) {
                const finalUrl = url.startsWith('http') ? url : `http://${url}`;
                allUrls.push(finalUrl);
              }
            }
          }
          console.log(`  Processed JSON from ${source.name}`);
        } catch (e) {
          console.error(`  JSON parse error for ${source.name}: ${e.message}`);
        }
      } else if (source.type === 'csv') {
        const csvUrls = extractURLsFromCSV(raw, source.urlIndex);
        allUrls.push(...csvUrls);
        console.log(`  ${csvUrls.length} URLs from ${source.name}`);
      }
    } catch (err) {
      console.error(`  Error fetching ${source.name}: ${err.message}`);
    }
  }
  return allUrls;
}

(async () => {
  try {
    let existing = [];
    if (fs.existsSync(SCAM_FILE)) {
      existing = JSON.parse(fs.readFileSync(SCAM_FILE, 'utf8'));
    }
    const initialLength = existing.length;
    const newUrls = await fetchAll();
    const all = [...new Set([...existing, ...newUrls])];
    fs.writeFileSync(SCAM_FILE, JSON.stringify(all, null, 2));
    console.log(`\n✅ Total scams saved: ${all.length} (${all.length - initialLength} new)`);
  } catch (e) {
    console.error('❌ Fatal scraper error:', e.message);
    process.exit(1);
  }
})();
