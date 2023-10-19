#!/usr/bin/with-contenv bashio

CERT_DIR=/ssl/lego
WORK_DIR=/data/workdir

# lego
LE_UPDATE="0"

# DuckDNS
if bashio::config.has_value "ipv4"; then IPV4=$(bashio::config 'ipv4'); else IPV4=""; fi
if bashio::config.has_value "ipv6"; then IPV6=$(bashio::config 'ipv6'); else IPV6=""; fi
DOMAIN_NAME=$(bashio::config 'domains | join(",")')
EMAIL=$(bashio::config 'email')
TOKEN=$(bashio::config 'token')
DNS_PROVIDER=$(bashio::config 'provider')
WAIT_TIME=$(bashio::config 'seconds')
KEY_TYPE=$(bashio::config 'lets_encrypt.algo')
CERTFILE=$(bashio::config 'lets_encrypt.certfile')
KEYFILE=$(bashio::config 'lets_encrypt.keyfile')

# Function set_os sets the os if needed and validates the value.
function set_os() {

    os="$(uname -s)"
    case "$os" in

    'Darwin')
        os='darwin'
        ;;
    'FreeBSD')
        os='freebsd'
        ;;
    'Linux')
        os='linux'
        ;;
    'OpenBSD')
        os='openbsd'
        ;;
    esac

    # Validate.
    case "$os" in

    'darwin' | 'freebsd' | 'linux' | 'openbsd')
        # All right, go on.
        ;;
    *)
        bashio::log.error "unsupported operating system: $(echo -n "${os}")"
        ;;
    esac

    # Log.
    bashio::log.info "operating system: $(echo -n "${os}")"
}

# Function set_cpu sets the cpu if needed and validates the value.
function set_cpu() {

    cpu="$(uname -m)"
    case "$cpu" in

    'x86_64' | 'x86-64' | 'x64' | 'amd64')
        cpu='amd64'
        ;;
    'i386' | 'i486' | 'i686' | 'i786' | 'x86')
        cpu='386'
        ;;
    'armv5l')
        cpu='armv5'
        ;;
    'armv6l')
        cpu='armv6'
        ;;
    'armv7l' | 'armv8l')
        cpu='armv7'
        ;;
    'aarch64' | 'arm64')
        cpu='arm64'
        ;;
    'mips' | 'mips64')
        if is_little_endian; then
            cpu="${cpu}le"
        fi
        cpu="${cpu}_softfloat"
        ;;
    esac

    # Validate.
    case "$cpu" in

    'amd64' | '386' | 'armv5' | 'armv6' | 'armv7' | 'arm64')
        # All right, go on.
        ;;
    'mips64le_softfloat' | 'mips64_softfloat' | 'mipsle_softfloat' | 'mips_softfloat')
        # That's right too.
        ;;
    *)
        bashio::log.error "unsupported cpu: $(echo -n "${cpu}")"
        ;;
    esac

    # Log.
    bashio::log.info "cpu: $(echo -n "${cpu}")"
}

function download_lego() {
    legoDist="lego.tar.gz"
    etagFile="/data/.lego.etag"
    arch="_${os}_${cpu}.tar"
    releaseURL=$(curl -s "https://api.github.com/repos/go-acme/lego/releases/latest" | grep "browser_download_url" | grep "${arch}" | grep -o "https://[^\"]*")
    
    # If the lego executable doesn't exist then wipe our etags so that it gets re-downloaded
    if [ ! -f /data/lego ]; then
        rm -f ${etagFile} 
    fi

    bashio::log.info "Downloading the latest lego release from $(echo -n "${releaseURL}")"
    curl -L --etag-save ${etagFile} --etag-compare ${etagFile} "${releaseURL}" --output ${legoDist}

    if [ -f ${legoDist} ]; then
        bashio::log.info "Extracting the latest lego version"
        tar xvfz ${legoDist} -C /data
        rm ${legoDist}
    fi
}

function  run_lego_duckdns() {
    bashio::log.info "legoing $(echo -n "${domainName}") @ $(echo -n "${DNS_PROVIDER}")"
    if [ "${SERVER:-}" != "" ] &&
        [ "${EAB_KID:-}" != "" ] &&
        [ "${EAB_HMAC:-}" != "" ]; then
        if DUCKDNS_TOKEN="${TOKEN}" \
            ./data/lego \
            --accept-tos \
            --server "${SERVER:-}" \
            --eab --kid "${EAB_KID:-}" --hmac "${EAB_HMAC:-}" \
            --dns duckdns \
            --domains "${wildcardDomainName}" \
            --domains "${domainName}" \
            --email "${email}" \
            --cert.timeout 600 \
            --path "${CERT_DIR}" \
            --key-type "${KEY_TYPE}" \
            run
        then
            bashio::log.info "Successfully got certificate via EAB."
        else
            bashio::log.error "Failed to get certificate via EAB!"
        fi
    else
        if DUCKDNS_TOKEN="${TOKEN}" \
            ./data/lego \
            --accept-tos \
            --dns duckdns \
            --domains "${wildcardDomainName}" \
            --domains "${domainName}" \
            --email "${email}" \
            --cert.timeout 600 \
            --path "${CERT_DIR}" \
            --key-type "${KEY_TYPE}" \
            run \
            --preferred-chain="ISRG Root X1"
        then
            bashio::log.info "Successfully got certificate."
        else
            bashio::log.error "Failed to get certificate!"
        fi
    fi
}

function run_lego() {
    domainName="${DOMAIN_NAME}"
    wildcardDomainName="*.${DOMAIN_NAME}"
    email="${EMAIL}"

    case ${DNS_PROVIDER} in

    duckdns)
    	run_lego_duckdns
    	;;

    *)
        bashio::log.error "Unsupported DNS provider: $(echo -n "${DNS_PROVIDER}"). Only duckdns for now."
        ;;
    esac
}

function get_abs_filename() {
    echo -n "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}

function  copy_certificate() {
    certFileName="${DOMAIN_NAME}"

    bashio::log.info "Your certificate and key are available at:"
    bashio::log.info "$(get_abs_filename ${CERT_DIR}/certificates/_.${certFileName}.key)"
    bashio::log.info "$(get_abs_filename ${CERT_DIR}/certificates/_.${certFileName}.crt)"

    bashio::log.info "Copying to:"
    bashio::log.info "$(get_abs_filename /ssl/${CERTFILE})"
    bashio::log.info "$(get_abs_filename /ssl/${KEYFILE})"
    cp -f "${CERT_DIR}/certificates/_.${certFileName}.crt" "/ssl/${CERTFILE}"
    cp -f "${CERT_DIR}/certificates/_.${certFileName}.key"  "/ssl/${KEYFILE}"
}

# Function that performs a renew
function le_renew() {
    local domain_args=()
    local domain=''

    domain=$(bashio::config 'domains')

    bashio::log.info "Renew certificate for domain: $(echo -n "${domain}")"

    if DUCKDNS_TOKEN="${TOKEN}" \
        ./data/lego \
        --dns duckdns \
        --domains "${wildcardDomainName}" \
        --domains "${domainName}" \
        --email "${email}" \
        --path "${CERT_DIR}" \
        renew
    then
        bashio::log.info "Certificate successfully renewed."
    else
        bashio::log.warning "Certificate failed to renew!"
    fi

    copy_certificate
}

# Register/generate certificate if terms accepted
if bashio::config.true 'lets_encrypt.accept_terms'; then
    mkdir -p "${CERT_DIR}"
    
    bashio::log.info "Hello lego!"

    set_os
    set_cpu
    download_lego

    # Check if certificate present and will expire within 30 days
    if [ -f /ssl/${CERTFILE} ]
    then
        expiry="$(openssl x509 -enddate -noout -in /ssl/${CERTFILE} | cut -c10-29)"
        expiry="$(date -d "${expiry}" -D "%b %d %H:%M:%S %Y" +%s)"
    else
        expiry="$(date +%s)"
    fi
    now="$(date +%s)"
    
    if bashio::config.true 'lets_encrypt.accept_terms' && [ $((expiry - now)) -ge 2592000 ]
    then
        bashio::log.info "Certificate /ssl/$(echo -n "${CERTFILE}") is good for $(((expiry - now)/86400)) days."
    else
        bashio::log.info "Certificate /ssl/$(echo -n "${CERTFILE}") $(((expiry - now)/86400)) days left."
        
        run_lego
        copy_certificate
    fi

fi

# Run duckdns
while true; do

    [[ ${IPV4} != *:/* ]] && ipv4=${IPV4} || ipv4=$(curl -s -m 10 "${IPV4}")
    [[ ${IPV6} != *:/* ]] && ipv6=${IPV6} || ipv6=$(curl -s -m 10 "${IPV6}")

    # Get IPv6-address from host interface
    if [[ -n "$IPV6" && ${ipv6} != *:* ]]; then
        ipv6=
        bashio::cache.flush_all
        for addr in $(bashio::network.ipv6_address "$IPV6"); do
	    # Skip non-global addresses
	    if [[ ${addr} != fe80:* && ${addr} != fc* && ${addr} != fd* ]]; then
              ipv6=${addr%/*}
              break
            fi
        done
    fi

    # Update DuckDNS with ipv6 address
    bashio::log.info "Updating DynDNS record:"
    if [[ ${ipv6} == *:* ]]; then
        if answer="$(curl -s "https://www.duckdns.org/update?domains=${DOMAIN_NAME}&token=${TOKEN}&ipv6=${ipv6}&verbose=true")" && [ "${answer}" != 'KO' ]; then
            bashio::log.info "${answer}"
        else
            bashio::log.warning "${answer}"
        fi
    fi

    # Update DuckDNS with ipv4 address
    if [[ -z ${ipv4} || ${ipv4} == *.* ]]; then
        if answer="$(curl -s "https://www.duckdns.org/update?domains=${DOMAIN_NAME}&token=${TOKEN}&ip=${ipv4}&verbose=true")" && [ "${answer}" != 'KO' ]; then
            bashio::log.info "${answer}"
        else
            bashio::log.warning "${answer}"
        fi
    fi

    # Renew cert if it expires within 30 days
    expiry="$(openssl x509 -enddate -noout -in /ssl/${CERTFILE} | cut -c10-29)"
    expiry="$(date -d "${expiry}" -D "%b %d %H:%M:%S %Y" +%s)"
    now="$(date +%s)"
    if bashio::config.true 'lets_encrypt.accept_terms' && [ $((expiry - now)) -ge 2592000 ]
    then
        bashio::log.info "Certificate /ssl/$(echo -n "${CERTFILE}") good for $(((expiry - now)/86400)) more more days, no need to renew."
    else
        bashio::log.info "Certificate /ssl/$(echo -n "${CERTFILE}") has $(((expiry - now)/86400)) days left, renewing..."
        
        le_renew
    fi

    sleep "${WAIT_TIME}"
done
