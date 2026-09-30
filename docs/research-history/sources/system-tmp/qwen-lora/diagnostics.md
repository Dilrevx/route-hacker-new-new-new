# Interface diagnostics before training

All failed runs remain on the server, unchanged. No train hyperparameter or
evaluation rule was adjusted based on test scores.

1. Initial smoke: SentenceTransformers 5.6 tokenize() includes modality string
   metadata; move only tensors to CUDA. No optimizer step reached.
2. Smoke v2: get_peft_model injection produced finite gradients and an optimizer
   step, but assigning to auto_model did not replace the underlying model:
   auto_model is now a read-only property returning module.model. Saving through
   that property saved the full base module and unload() was absent. The unused
   ~7.6GB diagnostic checkpoint is retained remotely, never selected for training.
   Version3 replaces module.model and asserts a PeftModel plus adapter-only save.
3. Initial 8B run: installed SentenceTransformer.encode() unconditionally calls
   self.to(device), incompatible with accelerate's dispatch hooks. Version3
   preserves model.tokenize(), module forward and pooling but avoids moving the
   dispatched model, and normalizes the FP32 output. Inputs are moved to the
   embedding layer's actual device. No score was produced by the failed run.

Dependencies are peft 0.21.0 and accelerate 1.15.0, isolated under this run's
deps directory; pre-existing packages and checkpoints remain unchanged.
