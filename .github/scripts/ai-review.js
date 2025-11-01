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
// Keep a copy of full diff for accurate per-file summary before potential truncation
const fullDiff = diff;
if (diff.length > MAX_DIFF_CHARS) diff = diff.slice(0, MAX_DIFF_CHARS) + '\n...[truncated]';

// Compute a lightweight per-file summary of additions/removals so the AI
// explicitly knows which changes are additions vs deletions. This helps when
// commits were reverted or similar history tricks confuse analysis.
function computeChangeSummary(diffText) {
  const summary = {};
  // Try to split by git diff file headers. If none, treat whole diff as one chunk.
  const parts = diffText.split(/^diff --git /m);
  if (parts.length <= 1) {
    // no file headers; compute overall counts
    let added = 0, removed = 0;
    for (const line of diffText.split(/\r?\n/)) {
      if (line.startsWith('+++') || line.startsWith('---')) continue;
      if (line.startsWith('+')) added++;
      else if (line.startsWith('-')) removed++;
    }
    summary['<overall>'] = { added, removed };
    return summary;
  }

  // parts[0] may be leading metadata before the first diff header
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const lines = part.split(/\r?\n/);
    // header is the first line after the split, contains two paths; pick last token
    const headerLine = lines[0] || '';
    const headerTokens = headerLine.trim().split(/\s+/);
    const file = headerTokens.length ? headerTokens[headerTokens.length - 1] : `part-${i}`;

    let added = 0, removed = 0;
    for (const line of lines) {
      if (line.startsWith('+++') || line.startsWith('---')) continue;
      if (line.startsWith('+')) added++;
      else if (line.startsWith('-')) removed++;
    }
    summary[file] = { added, removed };
  }
  return summary;
}

const changeSummary = computeChangeSummary(fullDiff);


// Build prompt requesting ONLY JSON output
// New format: return a JSON object. Prefer the new shape with an array of problems:
// {
//   problems: [
//     {
//       file: "path/to/file",
//       start_line: 123,         // optional
//       end_line: 130,           // optional
//       snippet: "code snippet or diff excerpt", // optional
//       title: "short title for this problem",
//       body: "detailed description for this problem",
//       labels: ["bug"],        // optional
//       assignees: ["alice"]    // optional
//     }
//   ],
//   title: "overall issue title (optional)",
//   body: "overall issue body (optional)",
//   labels: [],
//   assignees: []
// }
// For backward compatibility the AI may return the older single-object format with problem_found/title/body.
const prompt = `
You are an automated code reviewer. Analyze the following git diff and identify all distinct problems or issues that a developer should address.

Return ONLY a single JSON object (no extra text, no surrounding backticks). Prefer this shape:

{
  "problems": [
    {
      "file": "path/to/file",
      "start_line": 10,
      "end_line": 12,
      "snippet": "relevant code lines or small diff excerpt",
      "title": "Short title for this specific problem",
      "body": "Detailed description and suggested fix for this specific problem",
      "labels": ["bug","security"],
      "assignees": ["username"]
    }
  ],
  "title": "Optional overall title",
  "body": "Optional overall body summary",
  "labels": ["ai-review"],
  "assignees": []
}

If no problems are found, return { "problems": [] } or { "problem_found": false } (for backward compatibility).

Important: do not include any markdown, commentary, or non-JSON text — only the JSON object.

Annotated change summary (JSON):
${JSON.stringify(changeSummary, null, 2)}

Raw diff (truncated to MAX_DIFF_CHARS if applicable):
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
      max_tokens: 3000,
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

    // New behavior: accept either the legacy single-issue response or the new
    // { problems: [...] } array response. Prefer problems array to allow multiple comments.
    const problems = Array.isArray(aiObj.problems) ? aiObj.problems : null;

    // If no problems array was provided, fall back to legacy problem_found flag
    if (!problems || problems.length === 0) {
      if (!safeBool(aiObj.problem_found)) {
        console.log('AI determined no problem.');
        process.exit(0);
      }
    }

    // Top-level title/body/labels/assignees will be used to create the issue.
    const topTitle = aiObj.title || (problems && problems.length ? `Automated code review — ${problems.length} issues found` : 'Automated code review found an issue');
    const topBody = aiObj.body || (problems && problems.length ? `The AI detected ${problems.length} problem(s). Detailed comments follow.` : 'AI reported an issue. Please review the diff and details.');

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

    console.log('Preparing to create an issue:', topTitle);
    // Create a single issue for this run and then post one comment per problem (if multiple problems provided).
    let created = null;
    try {
      created = await createIssue(topTitle, topBody, labels, assignees);
      console.log('Issue created:', created.html_url || created.url || ('#' + created.number));
    } catch (err) {
      console.error('Failed to create issue:', err.message || err);
      process.exit(1);
    }

    // If problems array exists, post each as a separate comment with file/line/snippet info
    if (problems && problems.length) {
      for (let i = 0; i < problems.length; i++) {
        const p = problems[i] || {};
        const pTitle = p.title || `Issue ${i + 1}`;
        const fileLine = p.file ? `File: \`${p.file}\`` : '';
        const lineRange = (p.start_line || p.end_line) ? ` (lines ${p.start_line || '?'}${p.end_line ? '-' + p.end_line : ''})` : '';
        const pBody = p.body || '';
        const snippet = p.snippet ? `\n\n\`\`\`\n${p.snippet}\n\`\`\`` : '';

        const commentBody = `### ${pTitle}\n\n${fileLine}${lineRange}\n\n${pBody}${snippet}\n\n_Reported by automated code review._`;
        try {
          const comment = await createComment(created.number, commentBody);
          console.log('Posted comment for problem', i + 1, comment.html_url || comment.url || ('#' + created.number));
        } catch (err) {
          console.warn('Failed to post comment for problem', i + 1, err.message || err);
        }
      }
      process.exit(0);
    }

    // Legacy single-issue flow: if no problems array but problem_found was true, use legacy fields
    const legacyTitle = topTitle;
    const legacyBody = topBody;
    console.log('No problems array present; created single legacy issue.');
  } catch (err) {
    console.error('Error in AI review script:', err);
    process.exit(1);
  }
})();