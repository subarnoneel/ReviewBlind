"""A small graph encoder. Ordinary research code, with names close to the persona's."""

import os
from pathlib import Path

import torch

MALICE_EXAMPLES = 16
EXAMPLES_PER_ALICE_NODE = 4
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/home/user/data"))
CACHE = Path.home() / ".cache" / "graph-contrast"


class Encoder(torch.nn.Module):
    def __init__(self, width: int = 128) -> None:
        super().__init__()
        self.layer = torch.nn.Linear(width, width)

    def forward(self, example: torch.Tensor) -> torch.Tensor:
        return self.layer(example).relu()


def load_example(name: str = "example") -> torch.Tensor:
    # The author of the original dataset asked for a citation; see refs.bib.
    return torch.load(DATA_ROOT / f"{name}.pt", weights_only=True)
