#!/usr/bin/env node
const { execSync } = require('child_process');
const https = require('https');

function run(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8' });
  } catch (e) {
    return '';
  }
}

const GITHUB_SHA = process.env.GITHUB_SHA || run('git rev-parse HEAD').trim();
const REPO = process.env.GITHUB_REPOSITORY || (run('git remote get-url origin').trim().replace(/.*github.com[:\/]/, '').replace(/\.git$/, ''));
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MAX_DIFF_CHARS = parseInt(process.env.MAX_DIFF_CHARS || '20000', 10);
const DEFAULT_ASSIGNEE = process.env.DEFAULT_ASSIGNEE || '';
const DEFAULT_LABELS = (process.env.DEFAULT_LABELS || 'ai-review').split(',').map(s => s.trim()).filter(Boolean);
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

if (!GITHUB_TOKEN) {
  console.error('GITHUB_TOKEN not provided');
  process.exit(1);
}
if (!OPENAI_API_KEY) {
  console.error('OPENAI_API_KEY not provided');
  process.exit(1);
}

// Compute diff vs previous commit (if exists)
let diff = '';
try {
  execSync(`git rev-parse ${GITHUB_SHA}^`, { stdio: 'ignore' });
  diff = run(`git diff --no-prefix --unified=0 ${GITHUB_SHA}^ ${GITHUB_SHA}`);
} catch (e) {
  diff = run(`git show ${GITHUB_SHA}`);
}
if (!diff) {
  console.log('No diff to analyze.');
  process.exit(0);
}
if (diff.length > MAX_DIFF_CHARS) diff = diff.slice(0, MAX_DIFF_CHARS) + '\n...[truncated]';

// Build prompt requesting ONLY JSON output
const prompt = `
You are an automated code reviewer. Analyze the following git diff and determine whether there is a problem that requires opening a GitHub issue.
Return ONLY a single JSON object (no extra text, no surrounding backticks) with these fields:
- problem_found: true or false
- title: short issue title (string) — present if problem_found is true
- body: detailed issue body (string) — present if problem_found is true
- labels: array of label strings (can be empty)
- assignees: array of usernames to assign (can be empty)

Diff:
${diff}
`;

// Call OpenAI Chat Completions API (v1/chat/completions)
function openaiChat(prompt, model) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'You are a precise code-review assistant. Answer only with JSON as requested.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: 800,
      temperature: 0.0
    });

    const req = https.request({
      hostname: 'api.openai.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Authorization': `Bearer ${OPENAI_API_KEY}`
      }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const content = (parsed.choices && parsed.choices[0] && (parsed.choices[0].message?.content || parsed.choices[0].text)) || '';
          resolve(content);
        } catch (err) {
          reject(new Error('OpenAI response parse error: ' + err.message + '\nRaw:' + data));
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function createIssue(title, body, labels = [], assignees = []) {
  return new Promise((resolve, reject) => {
    const post = JSON.stringify({ title, body, labels, assignees });
    const [owner, repo] = REPO.split('/');
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/issues`,
      method: 'POST',
      headers: {
        'User-Agent': 'ai-code-review-action',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(post)
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (err) {
          reject(new Error('GitHub response parse error: ' + err.message + '\nRaw:' + data));
        }
      });
    });
    req.on('error', reject);
    req.write(post);
    req.end();
  });
}

function getRepoLabels() {
  return new Promise((resolve, reject) => {
    const [owner, repo] = REPO.split('/');
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/labels?per_page=100`,
      method: 'GET',
      headers: {
        'User-Agent': 'ai-code-review-action',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const names = Array.isArray(parsed) ? parsed.map(l => l.name) : [];
          resolve(names);
        } catch (err) {
          reject(new Error('GitHub labels response parse error: ' + err.message + '\nRaw:' + data));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function findOpenIssueByTitle(title) {
  return new Promise((resolve, reject) => {
    const [owner, repo] = REPO.split('/');
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/issues?state=open&per_page=100`,
      method: 'GET',
      headers: {
        'User-Agent': 'ai-code-review-action',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (!Array.isArray(parsed)) return resolve(null);
          const found = parsed.find(i => (i.title || '').trim().toLowerCase() === (title || '').trim().toLowerCase());
          resolve(found || null);
        } catch (err) {
          reject(new Error('GitHub issues response parse error: ' + err.message + '\nRaw:' + data));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function createComment(issue_number, body) {
  return new Promise((resolve, reject) => {
    const post = JSON.stringify({ body });
    const [owner, repo] = REPO.split('/');
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/issues/${issue_number}/comments`,
      method: 'POST',
      headers: {
        'User-Agent': 'ai-code-review-action',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(post)
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (err) {
          reject(new Error('GitHub comment response parse error: ' + err.message + '\nRaw:' + data));
        }
      });
    });
    req.on('error', reject);
    req.write(post);
    req.end();
  });
}

function safeBool(val) {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'number') return val !== 0;
  if (typeof val === 'string') {
    const v = val.trim().toLowerCase();
    return v === 'true' || v === '1' || v === 'yes';
  }
  return false;
}

(async () => {
  try {
    console.log('Calling OpenAI to analyze diff (truncated to %d chars)', MAX_DIFF_CHARS);
    const aiReply = await openaiChat(prompt, OPENAI_MODEL);
    console.log('AI raw reply snippet:', aiReply.slice(0, 1000));

    // Try to extract JSON object from AI reply
    const jsonMatch = aiReply.match(/\{[\s\S]*\}$/);
    const jsonText = jsonMatch ? jsonMatch[0] : aiReply;
    let aiObj = null;
    try {
      aiObj = JSON.parse(jsonText);
    } catch (err) {
      console.error('Could not parse AI response as JSON:', err.message);
      console.error('Full AI reply:', aiReply);
      process.exit(0); // assume no problem to avoid false positives
    }

    // Interpret the AI's problem_found robustly (accept booleans, strings like 'true')
    if (!safeBool(aiObj.problem_found)) {
      console.log('AI determined no problem.');
      process.exit(0);
    }

    const title = aiObj.title || 'Automated code review found an issue';
    const body = aiObj.body || 'AI reported an issue. Please review the diff and details.';

    // Normalize labels: accept array or comma-separated string from AI
    let labels = [];
    if (Array.isArray(aiObj.labels) && aiObj.labels.length) {
      labels = aiObj.labels.map(s => String(s).trim()).filter(Boolean);
    } else if (typeof aiObj.labels === 'string' && aiObj.labels.trim()) {
      labels = aiObj.labels.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (!labels.length) labels = DEFAULT_LABELS;

    // Normalize assignees
    const assignees = (Array.isArray(aiObj.assignees) && aiObj.assignees.length) ? aiObj.assignees : (DEFAULT_ASSIGNEE ? [DEFAULT_ASSIGNEE] : []);

    // Validate labels against repository labels; fall back to DEFAULT_LABELS when none match
    let repoLabels = [];
    try {
      repoLabels = await getRepoLabels();
    } catch (err) {
      console.warn('Could not fetch repository labels, proceeding without label validation:', err.message);
    }
    if (Array.isArray(repoLabels) && repoLabels.length) {
      const validated = labels.filter(l => repoLabels.includes(l));
      if (validated.length) labels = validated;
      else {
        // try default labels
        const validatedDefault = DEFAULT_LABELS.filter(l => repoLabels.includes(l));
        if (validatedDefault.length) labels = validatedDefault;
        else labels = []; // no matching labels in repo
      }
    }

    console.log('Preparing to file or comment on issue:', title);
    // If an open issue with same title exists, add a comment instead of creating a new issue
    try {
      const existing = await findOpenIssueByTitle(title);
      if (existing) {
        console.log('Found existing open issue #' + existing.number + ' — adding comment.');
        const comment = await createComment(existing.number, body + '\n\n_Comment added by automated code review._');
        console.log('Comment posted:', comment.html_url || comment.url || ('#' + existing.number));
        process.exit(0);
      }
    } catch (err) {
      console.warn('Error checking for existing issues (will attempt to create):', err.message);
    }

    console.log('Creating issue:', title);
    const created = await createIssue(title, body, labels, assignees);
    console.log('Issue created:', created.html_url || created.url);
  } catch (err) {
    console.error('Error in AI review script:', err);
    process.exit(1);
  }
})();