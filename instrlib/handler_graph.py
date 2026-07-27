"""
instrlib.handler_graph

Hasse diagram utilities for handler priority resolution.

When multiple causation/suppression events fire simultaneously, the PEP
needs to decide which handler to invoke. Handlers are registered with keys
that are either a single event name (str) or a tuple of event names. A
tuple key handles the case where *all* of those events fired together.

The Hasse diagram orders these keys by subset relation: a handler for
("BlockAction", "WarnAction") takes priority over a handler for just
"BlockAction" alone.

Copied verbatim from instrlib-main — no modifications needed.
"""

from collections import defaultdict, deque
from typing import Any, Dict, List, Set, Tuple, Union


def generate_graph(
    dic: Dict[Union[str, Tuple[str, ...]], Any]
) -> Dict[Tuple[str, ...], List[Tuple[str, ...]]]:
    """Build a Hasse diagram from the handler registration dict."""
    hasse: Dict[Tuple[str, ...], List[Tuple[str, ...]]] = defaultdict(list)
    ranks: Dict[int, List[Set[str]]]                    = defaultdict(list)

    if dic:
        for key in dic.keys():
            key_set = set(key) if isinstance(key, tuple) else {key}
            rank    = len(key_set)
            ranks[rank].append(key_set)

        for rank in sorted(ranks.keys()):
            for current_key in ranks[rank]:
                hasse[tuple(current_key)] = []
                for shorter_rank in range(rank):
                    if shorter_rank in ranks:
                        for subset_key in ranks[shorter_rank]:
                            if subset_key < current_key:
                                hasse[tuple(current_key)].append(tuple(subset_key))

    return dict(_simplify(hasse))


def _simplify(
    hasse: Dict[Tuple[str, ...], List[Tuple[str, ...]]]
) -> Dict[Tuple[str, ...], List[Tuple[str, ...]]]:
    """Remove non-maximal subsets from each adjacency list."""
    result = defaultdict(list)
    for key, subsets in hasse.items():
        current_set = set(map(tuple, subsets))
        filtered    = [
            s for s in subsets
            if not any(set(s) < set(other) for other in current_set)
        ]
        result[key] = filtered
    return result


def maximal_elements(
    graph: Dict[Tuple[str, ...], List[Tuple[str, ...]]]
) -> Set[Tuple[str, ...]]:
    """Return all nodes with no incoming edges (maximal elements of the poset)."""
    all_nodes     = set(graph.keys())
    has_incoming  = set(n for neighbors in graph.values() for n in neighbors)
    return all_nodes - has_incoming


def max_element(
    graph:   Dict[Tuple[str, ...], List[Tuple[str, ...]]],
    element: Tuple[str, ...],
) -> Set[Union[str, Tuple[str, ...]]]:
    """
    Return the most-specific handler key(s) that cover the fired event names.

    Given a set of fired event names (element), walk the graph from the
    maximal elements downward to find the largest subsets of element that
    are registered as handler keys.
    """
    res:     Set[Tuple[str, ...]] = set()
    seen:    Set[Tuple[str, ...]] = set()
    res_set: Set[str]             = set()

    max_of_graph = maximal_elements(graph)
    queue        = deque(max_of_graph)

    while queue:
        p       = queue.pop()
        tuple_p = p if isinstance(p, tuple) else (p,)
        set_p   = set(tuple_p)

        if p in seen:
            continue
        seen.add(p)

        if set_p <= set(element) and not set_p <= res_set:
            res.add(p)
            res_set |= set_p
        elif set_p & set(element):
            for neighbor in graph.get(p, []):
                queue.append(neighbor)

    return {elem[0] if len(elem) == 1 else elem for elem in res}
