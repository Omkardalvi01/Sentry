import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'research'))
from benchmark import binary_metrics, resolve
from testbed import specification, truth

def test_ground_truth_is_independent_of_spec_membership():
    spec=specification('resource')
    positives={tuple(x) for x in truth('resource')['positive_endpoints']}
    assert ('GET','/private/export') in positives and '/private/export' not in spec['paths']
    assert ('GET','/v1/public') in positives and '/v1/public' in spec['paths']
    assert '/v1/mismatch' in spec['paths'] and ('GET','/v1/mismatch') not in positives

def test_metrics_count_extra_discoveries_as_false_positives():
    assert binary_metrics({('GET','/real')},{('GET','/real'),('GET','/fake')})['precision'] == .5
    assert resolve('/v2/items/42?x=1',specification('resource')) == '/v2/items/{id}'
