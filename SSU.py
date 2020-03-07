from argparse import ArgumentParser
from http import cookiejar
from shutil import rmtree
from glob import glob
from tqdm import tqdm
from math import log
import requests, Fs, sys, os

requests.packages.urllib3.disable_warnings()
unit_list = list(zip(['bytes','kB','MB','GB'], [0, 0, 1, 2]))

# Prepare Session
def generate_session(cert,fw,device_id,env):
    class block_all_cookies(cookiejar.CookiePolicy):
        return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
        netscape = True
        rfc2965 = hide_cookie2 = False

    s = requests.Session()
    s.cookies.set_policy(block_all_cookies())

    s.headers.update({
        'User-Agent': 'NintendoSDK Firmware/%s (platform:NX; did:%s; eid:%s)' % (
            fw,device_id,env)})
    s.cert = cert
    s.verify = False
    return s

# Prepare CDN urls
def make_urls(env,server_set,cdn_name,sun_name,device_id):
    base_url = 'https://{name}.hac.{env}.{server_set}.nintendo.net{endpoint}?device_id={device_id}'

    cdn_url = base_url.format(
        name=cdn_name,
        env=env,
        server_set=server_set,
        endpoint='{endpoint}',
        device_id=device_id)

    sun_url = base_url.format(
        name=sun_name,
        env=env,
        server_set=server_set,
        endpoint='/v1{endpoint}',
        device_id=device_id)
    return cdn_url, sun_url

# Get Title and Version
def update_meta(s,sun_url):
    r = s.get(sun_url.format(endpoint='/system_update_meta'))
    if r.status_code != 200:
        return False, r.status_code
    return r.json()['system_update_metas'][0].values()


# Downloads from URL source and saves to dest
def download(s,source,dest):
    name = os.path.basename(dest).split()[0]
    if os.path.exists(dest):
        dlded = os.path.getsize(dest)
        r = s.get(source,headers={'Range': 'bytes=%s-' % dlded})
        
        if r.headers['Server'] != 'openresty/1.9.7.4':
            return 0, dlded
        elif r.headers.get('Content-Range') is None:
            total_size = int(r.headers['Content-Length'])
        else:
            total_size = dlded + int(r.headers['Content-Length'])
            
        if dlded == total_size:
            return 0, total_size
        elif dlded < total_size:
            f = open(dest,'ab')
        else:
            dlded = 0
            f = open(dest,'wb')
    else:
        dlded = 0
        r = s.get(source)
        total_size = int(r.headers['Content-Length'])
        f = open(dest,'wb')
        
    chunk = 1000
    if total_size >= 10000:
        dl_iter = r.iter_content(chunk_size=chunk)
        init = dlded // chunk
        total = total_size // chunk
        for chunk in tqdm(dl_iter,initial=init,total=total,desc=name,unit='kb',smoothing=1,leave=False):
            f.write(chunk)
            dlded += len(chunk)
    else:
        f.write(r.content)
        dlded += len(r.content)
    f.close()
    return dlded, total_size

def download_cnmt(s,cdn,path,tid,v):
    endpoint = '/t/a/{title_id}/{version}'.format(title_id=tid,version=v)
    r = s.head(cdn.format(endpoint=endpoint))
    if r.status_code == 200 and 'X-Nintendo-Content-ID' in r.headers:
        cid = r.headers['X-Nintendo-Content-ID']
    else:
        print('Error in retrieving Content ID.')
        print('Title ID: %s' % tid)
        print('Version: %d' % v)
        print('Status: %s' % r.status_code)
        sys.exit(3)
    endpoint = '/c/a/' + cid
    download_loc = os.path.join(path,cid + '.nca')
    dldata = download(s,cdn.format(endpoint=endpoint),download_loc)
    nca = Fs.factory(download_loc)
    nca.open(file=download_loc)
    return nca[0].getCnmt().contentEntries, dldata[0], dldata[1]

def download_content(s,cdn,path,ncaid):
    endpoint = '/c/c/' + ncaid
    download_loc = os.path.join(path,ncaid + '.nca')
    dldata = download(s,cdn.format(endpoint=endpoint),download_loc)
    return dldata[0], dldata[1]

# Makes a Update Version human readable
def pretty_version(v):
    # build = v & 0xFFFF
    major = (v >> 26) & 0x1F
    middle = (v >> 20) & 0x1F
    minor = (v >> 16) & 0xF
    return '%d.%d.%d' % (major,middle,minor) #,build)

# Make a large size human readable
def pretty_size(num):
    if num > 1:
        exponent = min(int(log(num, 1000)), len(unit_list) - 1)
        quotient = float(num) / 1000**exponent
        unit, num_decimals = unit_list[exponent]
        format_string = '{:.%sf} {}' % (num_decimals)
        return format_string.format(quotient,unit)
    if num == 1:
        return '1 byte'
    return '0 bytes'

def parse_version(v,latest):
    v = v.replace('.','')

    if v.lower().startswith('l'):
        return latest, pretty_version(latest)

    if len(v) > 3:
        return int(v), pretty_version(int(v))

    v = '{:>03s}'.format(v)
    try:
        r = requests.get('https://yls8.mtheall.com/ninupdates/titlelist.php',params={'sys':'hac','csv':1})

        if r.status_code != 200:
            return False, 'Could not fetch Update Version to Title Version conversion list.\nStatus Code: %d' % r.status_code
    except Exception:
        return False, 'Could not fetch Update Version to Title Version conversion list.\nCould not connect to host.'

    _, _, ver, versions = r.text.split('\n')[1].split(',')
    ver = [ int(i[1:]) for i in ver.split()]
    versions = [ i.replace('.','') for i in versions.split() ]
    conversion_dict = dict(zip(versions,ver))

    if v not in conversion_dict:
        return False, 'Not a valid Update Version.'

    return conversion_dict[v], pretty_version(conversion_dict[v])

def convert(c,o,k):
    from prodinfo import to_pem
    try:
        cert, msg = to_pem(c,o,k)
    except Exception as e:
        cert, msg = False, 'Unable to parse %s!' % c
    if not cert:
        sys.exit(3)
    print('%s exported to %s' % (c,cert))
    return cert

if __name__ == '__main__':
    parse = ArgumentParser()
    parse.add_argument('--firmware',help='Set user agent firmware',default='5.1.0-3')
    parse.add_argument('--device-id',help='Set the device ID.',default='0000000000000000')
    parse.add_argument('--version',help='FW Version to download.',default='LATEST')
    parse.add_argument('--environment',help='Set the CDN Environment',default='lp1')
    parse.add_argument('--server-set',help='Set the CDN server set',default='d4c')
    parse.add_argument('--cdn-name',help='Set CDN server name',default='atumn')
    parse.add_argument('--sun-name',help='Set SUN CDN server name',default='sun')
    parse.add_argument('--certificate',help='Set client certificate path',default='cert.pem')
    parse.add_argument('--prodinfo-to-pem',help='Converts a PRODINFO to a PEM certificate.',default=None)
    parse.add_argument('--prodinfo',help='Converts a PRODINFO to a PEM certificate and continues the download.',default=None)
    parse.add_argument('--convert-out',help='The output file for the PEM certificate made from --prodinfo.',default='cert.pem')
    parse.add_argument('--ssl-kek',help='The ssl_rsa_kek key.',default=None)
    parse.add_argument('--pack-to-nsp',help='Pack the NCAs to a NSP.',default=False,action='store_true')
    parse.add_argument('--nsp-name',help='The name of the output NSP file.',default='System Update[$tid$][$update_version$][v$title_version$].nsp')
    parse.add_argument('--clean-nca',default=False,action='store_true')

    args = parse.parse_args()
        
    if args.prodinfo_to_pem is not None:
        convert(args.prodinfo_to_pem,args.convert_out,args.ssl_kek)
        sys.exit(0)

    if args.prodinfo:
        args.certificate = convert(args.prodinfo,args.convert_out,args.ssl_kek)

    print('Creating Session')
    s = generate_session(args.certificate,args.firmware,args.device_id,args.environment)
    cdn,sun = make_urls(args.environment,args.server_set,args.cdn_name,args.sun_name,args.device_id)

    print('Retrieving System Update Meta')
    title_id,latest = update_meta(s,sun)

    if not title_id:
        print('Error in retrieving system_update_metas.')
        print('Status: %d' % latest)
        sys.exit(3)

    ver,version = parse_version(args.version,latest)
    if not (ver and version):
        print(version)
        sys.exit(3)

    print('Official Firmware {pretty} (v{actual})'.format(pretty=version,actual=ver))

    if not os.path.exists('downloads'):
        os.mkdir('downloads')

    # ver = 65536
    # title_id = '01006a800016e800'
    download_dir = os.path.join('downloads','Firmware ' + version)
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)

    fw_dir = os.path.join(download_dir,'ncas')
    if not os.path.exists(fw_dir):
        os.mkdir(fw_dir)

    endpoint = '/t/s/{title_id}/{version}'.format(
                    title_id=title_id,
                    version=ver)

    r = s.head(cdn.format(endpoint=endpoint))
    if r.status_code == 200 and 'X-Nintendo-Content-ID' in r.headers:
        cid = r.headers['X-Nintendo-Content-ID']
    else:
        print('Error in retrieving CNMT Content ID.')
        print('Status: %d' % r.status_code)
        sys.exit(3)

    endpoint = '/c/s/{content_id}'.format(content_id=cid)
    cnmt_nca = os.path.join(fw_dir,cid + '.nca')
    download(s,cdn.format(endpoint=endpoint),cnmt_nca)

    nca = Fs.factory(cnmt_nca)
    nca.open(file=cnmt_nca)

    cnmt = nca[0].getCnmt()

    content_entries = []
    total_cnmt_downloaded = 0
    total_cnmt_size = 0
    print('Downloading Metadata')
    pbar = tqdm(total=len(cnmt.metaEntries),unit='cnmt',leave=True,desc='Downloading Metadata')
    for i in cnmt.metaEntries:
        pbar.desc = '%s v%d' % (i.titleId,i.version)
        entries, downloaded, size = download_cnmt(s,cdn,fw_dir,i.titleId,i.version)
        content_entries += entries
        total_cnmt_downloaded += downloaded
        total_cnmt_size += size
        pbar.update(1)
    pbar.desc = 'Metadata Downloaded'
    pbar.refresh()
    pbar.close()

    total_expected_content_size = 0
    for i in content_entries:
        total_expected_content_size += i.size

    total_actual_content_size = 0
    total_downloaded_content = 0
    print('Downloading Content')
    pbar = tqdm(total=len(content_entries),unit='nca',leave=True,desc='Downloading Content')
    for i in content_entries:
        pbar.desc = i.ncaId + '.nca'
        downloaded, size = download_content(s,cdn,fw_dir,i.ncaId)
        total_downloaded_content += downloaded
        total_actual_content_size += size
        pbar.update(1)
    pbar.desc = 'Content Downloaded'
    pbar.refresh()
    pbar.close()

    metrics = ''

    # download metrics
    metrics += '\nTotal Size: {}\n  Metadata Size: {}\n  Content Size: {}\n\nDownloaded: {}\n  Metadata: {}\n  Content: {}'.format(
        pretty_size(total_expected_content_size + total_cnmt_size),
        pretty_size(total_cnmt_size),
        pretty_size(total_expected_content_size),
        pretty_size(total_cnmt_downloaded + total_downloaded_content),
        pretty_size(total_cnmt_downloaded),
        pretty_size(total_downloaded_content))

    if args.pack_to_nsp:
        args.nsp_name = args.nsp_name.replace('$tid$',title_id).replace('$update_version$',version).replace('$title_version$',str(ver))
        print('Packing to %s' % args.nsp_name)
        nsp = Fs.Nsp.Nsp()
        nsp.path = os.path.join(download_dir,args.nsp_name)
        files = glob(os.path.join(fw_dir,'*.nca'))
        nsp.pack(files)
        nsp_size = os.path.getsize(nsp.path)

        # nsp metrics
        metrics += '\n\nNSP Size: {}'.format(pretty_size(nsp_size))

    if args.pack_to_nsp and args.clean_nca:
        rmtree(fw_dir)

    print(metrics)