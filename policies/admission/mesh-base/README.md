# The Mesh base admission pack

`asg/mesh_admission_base/1.0.0`: the operator's allow and deny lists (#55) and the base policy's
five rows (#64) and a witnessed-card row (#349) as an admission pack, decided by capsule-engine's admission evaluator (#178).
`pack-source.yaml` is the source, in evidencebook-skills' admission pack profile v0
(`docs/admission-pack-profile-v0.md` there). `pack-definition.json` is what it compiles to, and
it is what the plugin embeds and loads (`crates/evidence-plugin/src/admission/base.rs`), pinned by
`PACK_ID` and `DEFINITION_DIGEST`.

## Recompiling

After changing `pack-source.yaml`, compile it with evidencebook-skills' compiler (it needs that
repository's `requirements.txt` in a virtual environment). The output directory must be inside
that repository; copy the definition out and remove the directory:

```bash
cd evidencebook-skills
python3 scripts/pack_compile.py compile \
  ../capsules-plugin/policies/admission/mesh-base/pack-source.yaml --out packs/tmp-mesh-base
cp packs/tmp-mesh-base/pack-definition.json ../capsules-plugin/policies/admission/mesh-base/
rm -rf packs/tmp-mesh-base
```

The compiler prints the new `definition_digest`. Set `DEFINITION_DIGEST` in `base.rs` to it; until
then the plugin refuses to load the pack, and `the_embedded_pack_is_the_one_pinned` fails. A
threshold change also changes the constants in `base.rs`, which
`the_packs_rows_are_base_1s_with_its_thresholds` holds equal to the pack's.
