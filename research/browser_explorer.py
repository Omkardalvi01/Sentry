"""Browser acceptance checks for the real local endpoint investigation workflow."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]

def run(base):
    output=ROOT/'research/results/frontend';output.mkdir(parents=True,exist_ok=True)
    def get(path):
        with urlopen(base+path,timeout=10) as response:return json.load(response)
    scans=get('/api/explorer/scans?'+urlencode({'specTitle':'resource','specVersion':'1','target':'http://127.0.0.1:9001','limit':25}))['items']
    scan=next(s for s in scans if s.get('traceVersion') and s['status']=='completed')
    key=json.dumps(['resource','1','GET','/v1/protected'],separators=(',',':'))
    errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1000},accept_downloads=True)
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(base+'/#requests?'+urlencode({'api':json.dumps(['resource','1'],separators=(',',':')),'target':'http://127.0.0.1:9001','scanId':scan['id'],'kind':'check'}))
        page.wait_for_function("document.querySelector('#result-count').textContent.includes('matching requests')")
        page.locator('[data-filter="operationKey"]').select_option(key)
        page.wait_for_function("document.querySelector('#results-table tbody').textContent.includes('/v1/protected')")
        page.locator('[data-filter="strategy"]').select_option('auth_bypass')
        page.wait_for_function("document.querySelectorAll('#results-table tbody tr').length===1")
        assert '/v1/protected' in page.locator('#results-table tbody').inner_text()
        url=page.url;page.reload();page.wait_for_function("document.querySelectorAll('#results-table tbody tr').length===1")
        assert page.locator('[data-filter="operationKey"]').input_value()==key
        page.locator('#results-table tbody tr').first.focus();page.keyboard.press('Enter')
        assert page.locator('#detail').is_visible()
        page.get_by_role('tab',name='Comparisons',exact=True).click()
        page.wait_for_function("document.querySelector('#detail-body').textContent.includes('Authenticated comparison')")
        page.get_by_role('tab',name='Raw JSON',exact=True).click()
        assert 'Bearer fixture' not in page.locator('#detail-body').inner_text()
        page.keyboard.press('Escape');assert page.locator('#detail').is_hidden()
        with page.expect_download() as downloaded:page.locator('#export-json').click()
        export=output/'filtered-requests.json';downloaded.value.save_as(export)
        rows=json.loads(export.read_text());assert len(rows)==1 and rows[0]['strategy']=='auth_bypass'
        page.locator('#clear-filters').click();page.wait_for_function("document.querySelectorAll('#results-table tbody tr').length>1")
        page.locator('button[data-sort="duration"]').click()
        page.wait_for_function("document.querySelector('th[aria-sort]')?.textContent.includes('Duration')")
        values=page.locator('#results-table tbody tr').evaluate_all("rows=>rows.map(r=>r.children[5].textContent)")
        assert values
        page.locator('nav [data-view="traffic"]').click();page.wait_for_function("document.querySelector('#result-count').textContent.includes('matching traffic')")
        page.locator('#page-size').select_option('25');page.wait_for_function("document.querySelectorAll('#results-table tbody tr').length===25")
        first=page.locator('#results-table tbody tr').first.inner_text();page.locator('#next').click()
        page.wait_for_function("document.querySelector('#page-info').textContent.startsWith('26')")
        assert page.locator('#results-table tbody tr').first.inner_text()!=first
        page.locator('nav [data-view="endpoints"]').click();page.wait_for_function("document.querySelector('#result-count').textContent.includes('matching endpoints')")
        page.locator('#search').fill('/v1/protected');page.wait_for_function("document.querySelectorAll('#results-table tbody tr').length===1")
        page.locator('#results-table tbody tr').first.click();page.get_by_role('button',name='Scan this operation').click();page.locator('#scan-dialog').wait_for(state='visible')
        assert page.locator('#scan-scope').input_value()=='selected'
        assert page.locator('#scan-operation').input_value()==key
        page.locator('[data-header-name]').first.fill('Authorization');page.locator('[data-header-value]').first.fill('Bearer fixture')
        page.locator('#scan-rps').fill('1000');page.locator('#preview-scan').click()
        page.wait_for_function("!document.querySelector('#preview-panel').hidden")
        preview=page.locator('#preview-table tbody').inner_text()
        assert '/v1/protected' in preview and '/swagger.json' not in preview and '/private/export' not in preview
        assert 'zero requests sent' in page.locator('#preview-count').inner_text()
        page.screenshot(path=str(output/'scan-preview.png'),full_page=True)
        page.locator('#submit-scan').click()
        page.wait_for_function("document.querySelector('#scan-summary').textContent.includes('completed')",timeout=30000)
        page.wait_for_function("document.querySelector('#result-count').textContent.includes('matching requests')")
        new_id=urlencode({})
        from urllib.parse import parse_qs,urlsplit
        new_id=parse_qs(urlsplit(page.url).fragment.partition('?')[2])['scanId'][0]
        traces=get('/api/scans/'+new_id+'/requests?limit=500')['items']
        assert traces and all(o['path']=='/v1/protected' for row in traces for o in row['origins'])
        assert not any(row['strategy']=='shadow_path' for row in traces)
        assert sum(row['sent'] for row in traces)==get('/api/scans/'+new_id)['probesSent']
        page.screenshot(path=str(output/'requests-desktop.png'),full_page=True)
        page.locator('#results-table tbody tr').first.click();assert page.locator('#detail').is_visible()
        page.screenshot(path=str(output/'evidence-desktop.png'))
        page.locator('#close-detail').click()
        page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(output/'requests-mobile.png'),full_page=True)
        page.locator('#results-table tbody tr').first.click();assert page.locator('#detail').is_visible()
        page.screenshot(path=str(output/'evidence-mobile.png'))
        assert not errors,errors
        browser.close()
    result={'passed':True,'scan_id':new_id,'checks':['endpoint and strategy filters','deep-link reload','keyboard evidence selection','baseline/auth comparisons','credential redaction','filtered JSON export','sortable headers','traffic pagination','single-operation preview','real scoped scan','trace request counts','desktop and mobile evidence panels'],'page_errors':errors}
    (output/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--base',default='http://127.0.0.1:8088');args=parser.parse_args();run(args.base)
