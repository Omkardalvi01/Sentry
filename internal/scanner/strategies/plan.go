package strategies

import (
	"fmt"
	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/google/uuid"
	"strings"
)

// Plan is shared by live graph scans and reproducible spec-file experiments.
func Plan(ops []graph.OperationWithPath, cfg *model.ScanConfig) []*model.Probe {
	active := func(name string) bool {
		if len(cfg.Strategies) == 0 {
			return true
		}
		for _, s := range cfg.Strategies {
			if s == name {
				return true
			}
		}
		return false
	}
	documented := map[string]bool{}
	methods := map[string][]string{}
	for _, op := range ops {
		documented[op.Method+" "+op.PathTemplate] = true
		methods[op.PathTemplate] = append(methods[op.PathTemplate], op.Method)
	}
	selected := func(method, path string) bool {
		if len(cfg.SelectedOperations) == 0 {
			return true
		}
		for _, op := range cfg.SelectedOperations {
			if op.Method == method && op.Path == path {
				return true
			}
		}
		return false
	}
	probes := []*model.Probe{}
	seen := map[string]*model.Probe{}
	add := func(p *model.Probe, op *model.Operation) {
		if model.Mutating(p.Method) && !cfg.AllowMutating {
			return
		}
		if op != nil {
			model.ApplyOperation(p, *op)
		}
		p.Meta["specTitle"], p.Meta["specVersion"] = cfg.SpecTitle, cfg.SpecVer
		key := p.Strategy + " " + p.Method + " " + p.URL
		origin := model.OperationRef{Method: p.Method, Path: p.Path}
		if op != nil {
			origin.Method = op.Method
			origin.Path = op.PathTemplate
		}
		origin.Key = model.OperationKey(cfg.SpecTitle, cfg.SpecVer, origin.Method, origin.Path)
		if previous := seen[key]; previous != nil {
			exists := false
			for _, o := range previous.Origins {
				if o.Key == origin.Key {
					exists = true
				}
			}
			if !exists {
				previous.Origins = append(previous.Origins, origin)
			}
		} else {
			p.ID = uuid.NewString()
			p.Origins = []model.OperationRef{origin}
			seen[key] = p
			probes = append(probes, p)
		}
	}
	for _, op := range ops {
		if !selected(op.Method, op.PathTemplate) {
			continue
		}
		if op.Deprecated && active(model.StrategyDeprecatedAlive) {
			add(model.MakeProbe(cfg.Target, op.PathTemplate, op.Method, model.StrategyDeprecatedAlive, map[string]string{}), &op.Operation)
		}
		if active(model.StrategyVersionProbe) {
			if matches := versionRegex.FindStringSubmatchIndex(op.PathTemplate); matches != nil {
				var v int
				fmt.Sscan(op.PathTemplate[matches[4]:matches[5]], &v)
				for _, variant := range generateVersionVariants(op.PathTemplate, matches, v) {
					if documented[op.Method+" "+variant.path] {
						continue
					}
					add(model.MakeProbe(cfg.Target, variant.path, op.Method, model.StrategyVersionProbe, map[string]string{"direction": variant.direction, "originalPath": op.PathTemplate}), &op.Operation)
				}
			}
			for _, target := range generateTargetVersionVariants(cfg.Target) {
				add(model.MakeProbe(target, op.PathTemplate, op.Method, model.StrategyVersionProbe, map[string]string{"direction": "older", "originalTarget": cfg.Target}), &op.Operation)
			}
		}
	}
	if active(model.StrategyMethodProbe) {
		for _, op := range ops {
			if !selected(op.Method, op.PathTemplate) {
				continue
			}
			for _, method := range allHTTPMethods {
				if documented[method+" "+op.PathTemplate] {
					continue
				}
				p := model.MakeProbe(cfg.Target, op.PathTemplate, method, model.StrategyMethodProbe, map[string]string{"definedMethods": strings.Join(methods[op.PathTemplate], ",")})
				copy := op.Operation
				copy.Responses = ""
				add(p, &copy)
			}
		}
	}
	if active(model.StrategyShadowPath) {
		for _, observed := range cfg.PassiveCandidates {
			if !selected(observed.Method, observed.Path) || documented[observed.Method+" "+observed.Path] {
				continue
			}
			add(model.MakeProbe(cfg.Target, observed.Path, observed.Method, model.StrategyShadowPath, map[string]string{"passive": "true"}), nil)
		}
		for _, sp := range shadowPaths {
			if len(cfg.SelectedOperations) > 0 {
				continue
			}
			if documented[sp.method+" "+sp.path] {
				continue
			}
			add(model.MakeProbe(cfg.Target, sp.path, sp.method, model.StrategyShadowPath, map[string]string{"category": sp.category}), nil)
		}
	}
	return probes
}
