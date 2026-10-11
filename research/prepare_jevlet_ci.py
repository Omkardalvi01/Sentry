"""Create an UNTRAINED tiny Jevlet fixture for pipeline checks only.

No training, pretrained model download, production weights or accuracy claims.
The fixture exercises loading, HTTP, Kafka, persistence and inventory rules.
"""
import argparse
import json
import os
from pathlib import Path
import pickle
import sys

os.environ.setdefault('USE_TF', '0')
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'evaluation'))
    sys.path.insert(0, str(args.repo.resolve() / 'src'))
    import torch
    from transformers import AutoModel, BertTokenizerFast, DistilBertConfig
    from jevlet.data import TOKENS
    from jevlet.model import Jevlet
    from local_models import normal_baseline, LocalDetector
    torch.manual_seed(42)
    args.output.mkdir(parents=True, exist_ok=False)
    vocab = args.output / 'vocab.txt'
    vocab.write_text('\n'.join(['[PAD]', '[UNK]', '[CLS]', '[SEP]', '[MASK]',
                    'normal', 'anomalous', 'classify', 'this', 'api', 'exchange',
                    'method', 'path', 'request', 'response', 'get', 'post', ':', '/', '.', '?']), encoding='utf-8')
    tokenizer = BertTokenizerFast(vocab_file=str(vocab))
    tokenizer.add_special_tokens({'additional_special_tokens': list(TOKENS)})
    config = DistilBertConfig(vocab_size=len(tokenizer), n_layers=1, dim=64, hidden_dim=128,
                            n_heads=2, max_position_embeddings=512)
    model = Jevlet(AutoModel.from_config(config)).eval()
    model.tokenizer, model.max_length, model.source_revision = tokenizer, 384, 'untrained-ci-fixture'
    model.save(args.output / 'jevlet')
    with (args.output / 'baseline.pkl').open('wb') as stream:
        pickle.dump(normal_baseline([]), stream)
    (args.output / 'models.json').write_text(json.dumps({'jevlet': {'threshold':.5,
        'metrics': {'untrained_ci_fixture':True, 'accuracy_not_evaluated':True}}}), encoding='utf-8')
    event = {'method':'GET','path':'/ci','status_code':200}
    loaded = LocalDetector.load(args.output,'jevlet',args.repo,'cpu')
    assert loaded.predict(event)['evaluation_status'] == 'evaluated'
    print('UNTRAINED Jevlet CI fixture created. Not a production or accuracy checkpoint.')


if __name__ == '__main__':
    main()
