<!-- tracelane:classification: PUBLIC -->
# Providers

Tracelane gateway speaks to **150+ routable providers** through a single API surface:
the OpenAI-compatible `/v1/chat/completions`. There is no Anthropic-native
`/v1/messages` on the gateway — Anthropic models are reached through the same
OpenAI-shaped call and translated upstream. You point at
`https://gateway.tracelane.dev`, set the model string, and we route for you
(cross-provider failover is opt-in per request via the `X-Tracelane-Failover`
header, not a default).

## Supported providers

Two kinds of adapter sit behind that one surface, and what separates them is the
wire format — not how well the provider is supported.

**Native adapters** carry purpose-built request/response translators, because
their API shape differs enough from OpenAI's that a generic adapter would lose
fidelity: Bedrock's SigV4 signing, Anthropic's `messages` API, Google's
multi-modal parts.

**The OpenAI-compatible catalog** is every provider that already speaks the
OpenAI Chat Completions wire format. It is a data file —
[`crates/gateway/providers.tsv`](../../crates/gateway/providers.tsv) — rather than
a `match` arm per provider, and both tables below are generated from it (plus
the adapter fields on `ProviderRegistry`) by
[`scripts/ci/build-provider-catalog.py`](../../scripts/ci/build-provider-catalog.py),
whose `--check` mode refuses a stale table. This page used to enumerate them by
hand, and by the time the catalog landed the hand-written version was wrong by
more than a hundred entries.

Every value in the **Model prefixes** column is matched with `starts_with`. A
prefix containing `/` is tried before a bare one, and bare prefixes are tried
longest-first. A model string that matches nothing is a `400 unroutable_model`:
the router has no default provider, deliberately, so an unrecognised model can
never reach some other provider's key.

<!-- BEGIN GENERATED PROVIDER TABLE -->

### Native adapters

| Provider | ID | Model prefixes | Credential env var |
|---|---|---|---|
| Anthropic | `anthropic` | `claude` · `anthropic/` | `ANTHROPIC_API_KEY` |
| Google (Gemini) | `google` | `gemini` · `google/` | `GOOGLE_API_KEY` |
| Google Vertex AI | `vertex` | `vertex/` | `GOOGLE_VERTEX_SERVICE_ACCOUNT_JSON` |
| AWS Bedrock | `bedrock` | `bedrock/` | `AWS_ACCESS_KEY_ID` |
| Azure OpenAI | `azure` | `azure/` | `AZURE_OPENAI_API_KEY` |
| Cohere | `cohere` | `command` · `cohere/` | `COHERE_API_KEY` |

### OpenAI-compatible catalog

| Provider | ID | Default base URL | Base-URL override | API key env var | Model prefixes |
|---|---|---|---|---|---|
| 302.AI | `302ai` | `https://api.302.ai` | `302AI_BASE_URL` | `302AI_API_KEY` | `302ai/` |
| Abacus | `abacus` | `https://routellm.abacus.ai` | `ABACUS_BASE_URL` | `ABACUS_API_KEY` | `abacus/` |
| abliteration.ai | `abliteration-ai` | `https://api.abliteration.ai` | `ABLITERATION_AI_BASE_URL` | `ABLIT_KEY` | `abliteration-ai/` |
| ai&amp; | `aiand` | `https://api.aiand.com` | `AIAND_BASE_URL` | `AIAND_API_KEY` | `aiand/` |
| AI-ROUTER | `ai-router` | `https://api.ai-router.dev` | `AI_ROUTER_BASE_URL` | `AI_ROUTER_API_KEY` | `ai-router/` |
| Ai21 | `ai21` | `https://api.ai21.com` | `AI21_BASE_URL` | `AI21_API_KEY` | `ai21/` · `j2-` · `jamba` |
| AKI.IO | `aki-io` | `https://aki.io` | `AKI_IO_BASE_URL` | `AKI_IO_API_KEY` | `aki-io/` |
| Aleph Alpha | `aleph-alpha` | `https://api.aleph-alpha.com` | `ALEPH_ALPHA_BASE_URL` | `ALEPH_ALPHA_API_KEY` | `luminous` · `aleph-alpha/` |
| Alibaba | `alibaba` | `https://dashscope-intl.aliyuncs.com/compatible-mode` | `ALIBABA_BASE_URL` | `DASHSCOPE_API_KEY` | `alibaba/` |
| Alibaba (China) | `alibaba-cn` | `https://dashscope.aliyuncs.com/compatible-mode` | `ALIBABA_CN_BASE_URL` | `DASHSCOPE_API_KEY` | `alibaba-cn/` |
| Alibaba Coding Plan | `alibaba-coding-plan` | `https://coding-intl.dashscope.aliyuncs.com` | `ALIBABA_CODING_PLAN_BASE_URL` | `ALIBABA_CODING_PLAN_API_KEY` | `alibaba-coding-plan/` |
| Alibaba Coding Plan (China) | `alibaba-coding-plan-cn` | `https://coding.dashscope.aliyuncs.com` | `ALIBABA_CODING_PLAN_CN_BASE_URL` | `ALIBABA_CODING_PLAN_API_KEY` | `alibaba-coding-plan-cn/` |
| Alibaba Token Plan | `alibaba-token-plan` | `https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode` | `ALIBABA_TOKEN_PLAN_BASE_URL` | `ALIBABA_TOKEN_PLAN_API_KEY` | `alibaba-token-plan/` |
| Alibaba Token Plan (China) | `alibaba-token-plan-cn` | `https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode` | `ALIBABA_TOKEN_PLAN_CN_BASE_URL` | `ALIBABA_TOKEN_PLAN_API_KEY` | `alibaba-token-plan-cn/` |
| Ambient | `ambient` | `https://api.ambient.xyz` | `AMBIENT_BASE_URL` | `AMBIENT_API_KEY` | `ambient/` |
| AMD | `amd` | `https://developer.amd.com.cn/radeon/api` | `AMD_BASE_URL` | `AMD_API_KEY` | `amd/` |
| AnyAPI | `anyapi` | `https://api.anyapi.ai` | `ANYAPI_BASE_URL` | `ANYAPI_API_KEY` | `anyapi/` |
| Anyscale | `anyscale` | `https://api.endpoints.anyscale.com` | `ANYSCALE_BASE_URL` | `ANYSCALE_API_KEY` | `anyscale/` |
| Arcee | `arcee` | `https://api.arcee.ai/api` | `ARCEE_BASE_URL` | `ARCEE_API_KEY` | `arcee/` |
| Auriko | `auriko` | `https://api.auriko.ai` | `AURIKO_BASE_URL` | `AURIKO_API_KEY` | `auriko/` |
| Bailing | `bailing` | `https://api.tbox.cn/api/llm/v1/chat/completions` | `BAILING_BASE_URL` | `BAILING_API_TOKEN` | `bailing/` |
| Baseten | `baseten` | `https://bridge.baseten.co/v1/direct` | `BASETEN_BASE_URL` | `BASETEN_API_KEY` | `baseten/` |
| Berget.AI | `berget` | `https://api.berget.ai` | `BERGET_BASE_URL` | `BERGET_API_KEY` | `berget/` |
| Blue Claw | `blueclaw` | `https://openai.blueclaw.network` | `BLUECLAW_BASE_URL` | `BLUECLAW_API_KEY` | `blueclaw/` |
| Cerebras | `cerebras` | `https://api.cerebras.ai` | `CEREBRAS_BASE_URL` | `CEREBRAS_API_KEY` | `cerebras/` |
| Charm Hyper | `hyper` | `https://hyper.charm.land` | `HYPER_BASE_URL` | `HYPER_API_KEY` | `hyper/` |
| Chutes | `chutes` | `https://llm.chutes.ai` | `CHUTES_BASE_URL` | `CHUTES_API_KEY` | `chutes/` |
| Clarifai | `clarifai` | `https://api.clarifai.com/v2/ext/openai` | `CLARIFAI_BASE_URL` | `CLARIFAI_PAT` | `clarifai/` |
| Claudinio | `claudinio` | `https://api.claudin.io` | `CLAUDINIO_BASE_URL` | `CLAUDINIO_API_KEY` | `claudinio/` |
| ClinePass | `cline-pass` | `https://api.cline.bot/api` | `CLINE_PASS_BASE_URL` | `CLINE_API_KEY` | `cline-pass/` |
| CloudFerro Sherlock | `cloudferro-sherlock` | `https://api-sherlock.cloudferro.com/openai` | `CLOUDFERRO_SHERLOCK_BASE_URL` | `CLOUDFERRO_SHERLOCK_API_KEY` | `cloudferro-sherlock/` |
| Cloudflare Workers AI | `cloudflare` | `https://gateway.ai.cloudflare.com/v1/tracelane/workers-ai/openai` | `CLOUDFLARE_AI_GATEWAY_URL` | `CLOUDFLARE_API_KEY` | `@cf/` · `cloudflare/` |
| CoralBricks | `coralbricks` | `https://inference.coralbricks.ai` | `CORALBRICKS_BASE_URL` | `CORAL_API_KEY` | `coralbricks/` |
| Cortecs | `cortecs` | `https://api.cortecs.ai` | `CORTECS_BASE_URL` | `CORTECS_API_KEY` | `cortecs/` |
| CrofAI | `crof` | `https://crof.ai` | `CROF_BASE_URL` | `CROF_API_KEY` | `crof/` |
| CrossModel | `crossmodel` | `https://api.crossmodel.ai` | `CROSSMODEL_BASE_URL` | `CROSSMODEL_API_KEY` | `crossmodel/` |
| Crusoe | `crusoe` | `https://api.inference.crusoecloud.com` | `CRUSOE_BASE_URL` | `CRUSOE_API_KEY` | `crusoe/` |
| D.Run (China) | `drun` | `https://chat.d.run` | `DRUN_BASE_URL` | `DRUN_API_KEY` | `drun/` |
| DaoXE | `daoxe` | `https://daoxe.com` | `DAOXE_BASE_URL` | `DAOXE_API_KEY` | `daoxe/` |
| Deep Infra | `deepinfra` | `https://api.deepinfra.com` | `DEEPINFRA_BASE_URL` | `DEEPINFRA_API_KEY` | `deepinfra/` |
| DeepSeek | `deepseek` | `https://api.deepseek.com` | `DEEPSEEK_BASE_URL` | `DEEPSEEK_API_KEY` | `deepseek` |
| DigitalOcean | `digitalocean` | `https://inference.do-ai.run` | `DIGITALOCEAN_BASE_URL` | `DIGITALOCEAN_ACCESS_TOKEN` | `digitalocean/` |
| DInference | `dinference` | `https://api.dinference.com` | `DINFERENCE_BASE_URL` | `DINFERENCE_API_KEY` | `dinference/` |
| EBCloud | `ebcloud` | `https://maas-api.ebcloud.com` | `EBCLOUD_BASE_URL` | `EBCLOUD_API_KEY` | `ebcloud/` |
| Eden AI | `edenai` | `https://api.edenai.run/v3` | `EDENAI_BASE_URL` | `EDENAI_API_KEY` | `edenai/` |
| EmpirioLabs AI | `empiriolabs` | `https://api.empiriolabs.ai` | `EMPIRIOLABS_BASE_URL` | `EMPIRIOLABS_API_KEY` | `empiriolabs/` |
| evroc | `evroc` | `https://models.think.evroc.com` | `EVROC_BASE_URL` | `EVROC_API_KEY` | `evroc/` |
| FastRouter | `fastrouter` | `https://go.fastrouter.ai/api` | `FASTROUTER_BASE_URL` | `FASTROUTER_API_KEY` | `fastrouter/` |
| Fireworks AI | `fireworks` | `https://api.fireworks.ai/inference` | `FIREWORKS_BASE_URL` | `FIREWORKS_API_KEY` | `fireworks/` |
| Friendli | `friendli` | `https://api.friendli.ai/serverless` | `FRIENDLI_BASE_URL` | `FRIENDLI_TOKEN` | `friendli/` |
| FrogBot | `frogbot` | `https://app.frogbot.ai/api` | `FROGBOT_BASE_URL` | `FROGBOT_API_KEY` | `frogbot/` |
| GitHub Copilot | `github-copilot` | `https://api.githubcopilot.com` | `GITHUB_COPILOT_BASE_URL` | `GITHUB_TOKEN` | `github-copilot/` |
| GMI Cloud | `gmicloud` | `https://api.gmi-serving.com` | `GMICLOUD_BASE_URL` | `GMICLOUD_API_KEY` | `gmicloud/` |
| GreenPT | `greenpt` | `https://api.greenpt.ai` | `GREENPT_BASE_URL` | `GREENPT_API_KEY` | `greenpt/` |
| Groq | `groq` | `https://api.groq.com/openai` | `GROQ_BASE_URL` | `GROQ_API_KEY` | `llama` · `qwen` · `gemma` |
| Helicone | `helicone` | `https://ai-gateway.helicone.ai` | `HELICONE_BASE_URL` | `HELICONE_API_KEY` | `helicone/` |
| Hetzner | `hetzner` | `https://inference.hetzner.com/api` | `HETZNER_BASE_URL` | `HETZNER_API_KEY` | `hetzner/` |
| HPC-AI | `hpc-ai` | `https://api.hpc-ai.com/inference` | `HPC_AI_BASE_URL` | `HPC_AI_API_KEY` | `hpc-ai/` |
| Hugging Face | `huggingface` | `https://api-inference.huggingface.co` | `HUGGINGFACE_BASE_URL` | `HUGGINGFACE_API_KEY` | `hf/` · `huggingface/` |
| Hyperbolic | `hyperbolic` | `https://api.hyperbolic.xyz` | `HYPERBOLIC_BASE_URL` | `HYPERBOLIC_API_KEY` | `hyperbolic/` |
| iFlow | `iflowcn` | `https://apis.iflow.cn` | `IFLOWCN_BASE_URL` | `IFLOW_API_KEY` | `iflowcn/` |
| Impossibl | `impossibl` | `https://api.impossibl.com` | `IMPOSSIBL_BASE_URL` | `IMPOSSIBL_API_KEY` | `impossibl/` |
| Inception | `inception` | `https://api.inceptionlabs.ai` | `INCEPTION_BASE_URL` | `INCEPTION_API_KEY` | `inception/` |
| Inceptron | `inceptron` | `https://api.inceptron.io` | `INCEPTRON_BASE_URL` | `INCEPTRON_API_KEY` | `inceptron/` |
| Inference | `inference` | `https://inference.net` | `INFERENCE_BASE_URL` | `INFERENCE_API_KEY` | `inference/` |
| InferX | `inferx` | `https://model.inferx.net/endpoints` | `INFERX_BASE_URL` | `INFERX_API_KEY` | `inferx/` |
| IO.NET | `io-net` | `https://api.intelligence.io.solutions/api` | `IO_NET_BASE_URL` | `IOINTELLIGENCE_API_KEY` | `io-net/` |
| Jalapeno Cloud | `jalapeno` | `https://api.jalapeno-cloud.ai` | `JALAPENO_BASE_URL` | `JALAPENO_API_KEY` | `jalapeno/` |
| Jiekou.AI | `jiekou` | `https://api.jiekou.ai/openai` | `JIEKOU_BASE_URL` | `JIEKOU_API_KEY` | `jiekou/` |
| Kenari | `kenari` | `https://kenari.id` | `KENARI_BASE_URL` | `KENARI_API_KEY` | `kenari/` |
| Kilo Gateway | `kilo` | `https://api.kilo.ai/api/gateway` | `KILO_BASE_URL` | `KILO_API_KEY` | `kilo/` |
| Kosmik Compute | `kosmik` | `https://api.koscompute.com` | `KOSMIK_BASE_URL` | `KOSMIK_API_KEY` | `kosmik/` |
| KUAE Cloud Coding Plan | `kuae-cloud-coding-plan` | `https://coding-plan-endpoint.kuaecloud.net` | `KUAE_CLOUD_CODING_PLAN_BASE_URL` | `KUAE_API_KEY` | `kuae-cloud-coding-plan/` |
| Lambda | `lambda` | `https://api.lambdalabs.com` | `LAMBDA_BASE_URL` | `LAMBDA_API_KEY` | `lambda/` |
| Lepton | `lepton` | `https://llama3-1-405b.lepton.run` | `LEPTON_BASE_URL` | `LEPTON_API_KEY` | `lepton/` |
| Lilac | `lilac` | `https://api.getlilac.com` | `LILAC_BASE_URL` | `LILAC_API_KEY` | `lilac/` |
| Llama | `llama` | `https://api.llama.com/compat` | `LLAMA_BASE_URL` | `LLAMA_API_KEY` | `llama/` |
| LLM Gateway | `llmgateway` | `https://api.llmgateway.io` | `LLMGATEWAY_BASE_URL` | `LLMGATEWAY_API_KEY` | `llmgateway/` |
| LLMTR | `llmtr` | `https://llmtr.com` | `LLMTR_BASE_URL` | `LLMTR_API_KEY` | `llmtr/` |
| LongCat | `longcat` | `https://api.longcat.chat/openai` | `LONGCAT_BASE_URL` | `LONGCAT_API_KEY` | `longcat/` |
| LucidQuery | `lucidquery` | `https://api.lucidquery.com` | `LUCIDQUERY_BASE_URL` | `LUCIDQUERY_API_KEY` | `lucidquery/` |
| Meganova | `meganova` | `https://api.meganova.ai` | `MEGANOVA_BASE_URL` | `MEGANOVA_API_KEY` | `meganova/` |
| Mistral | `mistral` | `https://api.mistral.ai` | `MISTRAL_BASE_URL` | `MISTRAL_API_KEY` | `mistral` · `mixtral` |
| Mixlayer | `mixlayer` | `https://models.mixlayer.ai` | `MIXLAYER_BASE_URL` | `MIXLAYER_API_KEY` | `mixlayer/` |
| Moark | `moark` | `https://moark.com` | `MOARK_BASE_URL` | `MOARK_API_KEY` | `moark/` |
| Modal | `modal` | `https://api.modal.com/v1/openai` | `MODAL_BASE_URL` | `MODAL_API_KEY` | `modal/` |
| Model Oracle AI | `model-oracle-ai` | `https://api.modeloracle.com/api` | `MODEL_ORACLE_AI_BASE_URL` | `MODEL_ORACLE_API_KEY` | `model-oracle-ai/` |
| Modelis | `modelis` | `https://modelishub.com` | `MODELIS_BASE_URL` | `MODELIS_API_KEY` | `modelis/` |
| ModelScope | `modelscope` | `https://api-inference.modelscope.cn` | `MODELSCOPE_BASE_URL` | `MODELSCOPE_API_KEY` | `modelscope/` |
| Moonshot AI | `moonshot` | `https://api.moonshot.cn` | `MOONSHOT_BASE_URL` | `MOONSHOT_API_KEY` | `moonshot/` |
| Moonshot AI (China) | `moonshotai-cn` | `https://api.moonshot.cn` | `MOONSHOTAI_CN_BASE_URL` | `MOONSHOT_API_KEY` | `moonshotai-cn/` |
| Morph | `morph` | `https://api.morphllm.com` | `MORPH_BASE_URL` | `MORPH_API_KEY` | `morph/` |
| NanoGPT | `nano-gpt` | `https://nano-gpt.com/api` | `NANO_GPT_BASE_URL` | `NANO_GPT_API_KEY` | `nano-gpt/` |
| NEAR AI Cloud | `nearai` | `https://cloud-api.near.ai` | `NEARAI_BASE_URL` | `NEARAI_API_KEY` | `nearai/` |
| Nebius Token Factory | `nebius` | `https://api.tokenfactory.nebius.com` | `NEBIUS_BASE_URL` | `NEBIUS_API_KEY` | `nebius/` |
| Neuralwatt | `neuralwatt` | `https://api.neuralwatt.com` | `NEURALWATT_BASE_URL` | `NEURALWATT_API_KEY` | `neuralwatt/` |
| Nova | `nova` | `https://api.nova.amazon.com` | `NOVA_BASE_URL` | `NOVA_API_KEY` | `nova/` |
| NovitaAI | `novita` | `https://api.novita.ai` | `NOVITA_BASE_URL` | `NOVITA_API_KEY` | `novita/` |
| Nvidia | `nvidia` | `https://integrate.api.nvidia.com` | `NVIDIA_BASE_URL` | `NVIDIA_API_KEY` | `nvidia/` |
| Ofox | `ofox` | `https://api.ofox.ai` | `OFOX_BASE_URL` | `OFOX_API_KEY` | `ofox/` |
| Ollama | `ollama` | `http://localhost:11434` | `OLLAMA_BASE_URL` | _none — local_ | `ollama/` |
| Ollama Cloud | `ollama-cloud` | `https://ollama.com` | `OLLAMA_CLOUD_BASE_URL` | `OLLAMA_API_KEY` | `ollama-cloud/` |
| OpenAI | `openai` | `https://api.openai.com` | `OPENAI_BASE_URL` | `OPENAI_API_KEY` | `gpt` · `openai/` · `o1` · `o3` · `text-embedding-` |
| OpenCode Go | `opencode-go` | `https://opencode.ai/zen/go` | `OPENCODE_GO_BASE_URL` | `OPENCODE_API_KEY` | `opencode-go/` |
| OpenCode Zen | `opencode` | `https://opencode.ai/zen` | `OPENCODE_BASE_URL` | `OPENCODE_API_KEY` | `opencode/` |
| OpenRouter | `openrouter` | `https://openrouter.ai/api` | `OPENROUTER_BASE_URL` | `OPENROUTER_API_KEY` | `openrouter/` |
| OrcaRouter | `orcarouter` | `https://api.orcarouter.ai` | `ORCAROUTER_BASE_URL` | `ORCAROUTER_API_KEY` | `orcarouter/` |
| OVHcloud AI Endpoints | `ovhcloud` | `https://oai.endpoints.kepler.ai.cloud.ovh.net` | `OVHCLOUD_BASE_URL` | `OVHCLOUD_API_KEY` | `ovhcloud/` |
| Perplexity | `perplexity` | `https://api.perplexity.ai` | `PERPLEXITY_BASE_URL` | `PERPLEXITY_API_KEY` | `sonar` · `perplexity/` · `llama-3.1-sonar` |
| Pioneer | `pioneer` | `https://api.pioneer.ai` | `PIONEER_BASE_URL` | `PIONEER_API_KEY` | `pioneer/` |
| Poe | `poe` | `https://api.poe.com` | `POE_BASE_URL` | `POE_API_KEY` | `poe/` |
| Poolside | `poolside` | `https://inference.poolside.ai` | `POOLSIDE_BASE_URL` | `POOLSIDE_API_KEY` | `poolside/` |
| Predibase | `predibase` | `https://serving.app.predibase.com` | `PREDIBASE_BASE_URL` | `PREDIBASE_API_KEY` | `predibase/` |
| QiHang | `qihang-ai` | `https://api.qhaigc.net` | `QIHANG_AI_BASE_URL` | `QIHANG_API_KEY` | `qihang-ai/` |
| Qiniu | `qiniu-ai` | `https://api.qnaigc.com` | `QINIU_AI_BASE_URL` | `QINIU_API_KEY` | `qiniu-ai/` |
| Regolo AI | `regolo-ai` | `https://api.regolo.ai` | `REGOLO_AI_BASE_URL` | `REGOLO_API_KEY` | `regolo-ai/` |
| Requesty | `requesty` | `https://router.requesty.ai` | `REQUESTY_BASE_URL` | `REQUESTY_API_KEY` | `requesty/` |
| routing.run | `routing-run` | `https://api.routing.run` | `ROUTING_RUN_BASE_URL` | `ROUTING_RUN_API_KEY` | `routing-run/` |
| RunInfra | `runinfra` | `https://api.runinfra.ai` | `RUNINFRA_BASE_URL` | `RUNINFRA_GATEWAY_KEY` | `runinfra/` |
| Sakana AI | `sakana` | `https://api.sakana.ai` | `SAKANA_BASE_URL` | `SAKANA_API_KEY` | `sakana/` |
| Sambanova | `sambanova` | `https://api.sambanova.ai` | `SAMBANOVA_BASE_URL` | `SAMBANOVA_API_KEY` | `sambanova/` |
| Sarvam AI | `sarvam` | `https://api.sarvam.ai` | `SARVAM_BASE_URL` | `SARVAM_API_KEY` | `sarvam/` |
| Scaleway | `scaleway` | `https://api.scaleway.ai` | `SCALEWAY_BASE_URL` | `SCALEWAY_API_KEY` | `scaleway/` |
| SCNet Token Plan | `scnet-token-plan` | `https://api.scnet.cn/api/llm` | `SCNET_TOKEN_PLAN_BASE_URL` | `SCNET_API_KEY` | `scnet-token-plan/` |
| SCX.ai | `scx` | `https://api.scx.ai` | `SCX_BASE_URL` | `SCX_API_KEY` | `scx/` |
| SiliconFlow | `siliconflow` | `https://api.siliconflow.com` | `SILICONFLOW_BASE_URL` | `SILICONFLOW_API_KEY` | `siliconflow/` |
| SiliconFlow (China) | `siliconflow-cn` | `https://api.siliconflow.cn` | `SILICONFLOW_CN_BASE_URL` | `SILICONFLOW_CN_API_KEY` | `siliconflow-cn/` |
| STACKIT | `stackit` | `https://api.openai-compat.model-serving.eu01.onstackit.cloud` | `STACKIT_BASE_URL` | `STACKIT_API_KEY` | `stackit/` |
| StepFun (China) | `stepfun` | `https://api.stepfun.com` | `STEPFUN_BASE_URL` | `STEPFUN_API_KEY` | `stepfun/` |
| StepFun (Global) | `stepfun-ai` | `https://api.stepfun.ai` | `STEPFUN_AI_BASE_URL` | `STEPFUN_API_KEY` | `stepfun-ai/` |
| StepFun Step Plan (China) | `stepfun-step-plan` | `https://api.stepfun.com/step_plan` | `STEPFUN_STEP_PLAN_BASE_URL` | `STEPFUN_API_KEY` | `stepfun-step-plan/` |
| StepFun Step Plan (Global) | `stepfun-ai-step-plan` | `https://api.stepfun.ai/step_plan` | `STEPFUN_AI_STEP_PLAN_BASE_URL` | `STEPFUN_API_KEY` | `stepfun-ai-step-plan/` |
| submodel | `submodel` | `https://llm.submodel.ai` | `SUBMODEL_BASE_URL` | `SUBMODEL_INSTAGEN_ACCESS_KEY` | `submodel/` |
| Synthetic | `synthetic` | `https://api.synthetic.new/openai` | `SYNTHETIC_BASE_URL` | `SYNTHETIC_API_KEY` | `synthetic/` |
| Tencent Coding Plan (China) | `tencent-coding-plan` | `https://api.lkeap.cloud.tencent.com/coding/v3` | `TENCENT_CODING_PLAN_BASE_URL` | `TENCENT_CODING_PLAN_API_KEY` | `tencent-coding-plan/` |
| Tencent Token Plan | `tencent-token-plan` | `https://api.lkeap.cloud.tencent.com/plan/v3` | `TENCENT_TOKEN_PLAN_BASE_URL` | `TENCENT_TOKEN_PLAN_API_KEY` | `tencent-token-plan/` |
| Tencent TokenHub | `tencent-tokenhub` | `https://tokenhub.tencentmaas.com` | `TENCENT_TOKENHUB_BASE_URL` | `TENCENT_TOKENHUB_API_KEY` | `tencent-tokenhub/` |
| TensorX | `tensorx` | `https://api.tensorx.ai` | `TENSORX_BASE_URL` | `TENSORX_API_KEY` | `tensorx/` |
| The Grid AI | `the-grid-ai` | `https://api.thegrid.ai` | `THE_GRID_AI_BASE_URL` | `THEGRID_API_KEY` | `the-grid-ai/` |
| Tinfoil | `tinfoil` | `https://inference.tinfoil.sh` | `TINFOIL_BASE_URL` | `TINFOIL_API_KEY` | `tinfoil/` |
| Together AI | `together` | `https://api.together.xyz` | `TOGETHER_BASE_URL` | `TOGETHER_API_KEY` | `together/` |
| TrustedRouter | `trustedrouter` | `https://api.trustedrouter.com` | `TRUSTEDROUTER_BASE_URL` | `TRUSTEDROUTER_API_KEY` | `trustedrouter/` |
| Umans AI | `umans-ai` | `https://api.code.umans.ai` | `UMANS_AI_BASE_URL` | `UMANS_AI_API_KEY` | `umans-ai/` |
| Umans AI Coding Plan | `umans-ai-coding-plan` | `https://api.code.umans.ai` | `UMANS_AI_CODING_PLAN_BASE_URL` | `UMANS_AI_CODING_PLAN_API_KEY` | `umans-ai-coding-plan/` |
| UnoRouter | `unorouter` | `https://api.unorouter.com` | `UNOROUTER_BASE_URL` | `UNOROUTER_API_KEY` | `unorouter/` |
| Upstage | `upstage` | `https://api.upstage.ai` | `UPSTAGE_BASE_URL` | `UPSTAGE_API_KEY` | `solar-` · `upstage/` |
| Vultr | `vultr` | `https://api.vultrinference.com` | `VULTR_BASE_URL` | `VULTR_API_KEY` | `vultr/` |
| Wafer | `wafer.ai` | `https://pass.wafer.ai` | `WAFER_AI_BASE_URL` | `WAFER_API_KEY` | `wafer.ai/` |
| Weights &amp; Biases | `wandb` | `https://api.inference.wandb.ai` | `WANDB_BASE_URL` | `WANDB_API_KEY` | `wandb/` |
| xAI | `xai` | `https://api.x.ai` | `XAI_BASE_URL` | `XAI_API_KEY` | `grok` · `xai/` |
| Xiaomi | `xiaomi` | `https://api.xiaomimimo.com` | `XIAOMI_BASE_URL` | `XIAOMI_API_KEY` | `xiaomi/` |
| Xiaomi Token Plan (China) | `xiaomi-token-plan-cn` | `https://token-plan-cn.xiaomimimo.com` | `XIAOMI_TOKEN_PLAN_CN_BASE_URL` | `XIAOMI_API_KEY` | `xiaomi-token-plan-cn/` |
| Xiaomi Token Plan (Europe) | `xiaomi-token-plan-ams` | `https://token-plan-ams.xiaomimimo.com` | `XIAOMI_TOKEN_PLAN_AMS_BASE_URL` | `XIAOMI_API_KEY` | `xiaomi-token-plan-ams/` |
| Xiaomi Token Plan (Singapore) | `xiaomi-token-plan-sgp` | `https://token-plan-sgp.xiaomimimo.com` | `XIAOMI_TOKEN_PLAN_SGP_BASE_URL` | `XIAOMI_API_KEY` | `xiaomi-token-plan-sgp/` |
| Xpersona | `xpersona` | `https://www.xpersona.co` | `XPERSONA_BASE_URL` | `XPERSONA_API_KEY` | `xpersona/` |
| Yi | `yi` | `https://api.01.ai` | `YI_BASE_URL` | `YI_API_KEY` | `yi-` · `yi/` |
| Z.AI | `zai` | `https://api.z.ai/api/paas/v4` | `ZAI_BASE_URL` | `ZHIPU_API_KEY` | `zai/` |
| Z.AI Coding Plan | `zai-coding-plan` | `https://api.z.ai/api/coding/paas/v4` | `ZAI_CODING_PLAN_BASE_URL` | `ZHIPU_API_KEY` | `zai-coding-plan/` |
| Zeldoc | `zeldoc` | `https://api.zeldoc.ai` | `ZELDOC_BASE_URL` | `ZELDOC_API_KEY` | `zeldoc/` |
| Zenifra | `zenifra` | `https://ai.zenifra.com` | `ZENIFRA_BASE_URL` | `ZENIFRA_AI_KEY` | `zenifra/` |
| ZenMux | `zenmux` | `https://zenmux.ai/api` | `ZENMUX_BASE_URL` | `ZENMUX_API_KEY` | `zenmux/` |
| Zhipu AI | `zhipuai` | `https://open.bigmodel.cn/api/paas/v4` | `ZHIPUAI_BASE_URL` | `ZHIPU_API_KEY` | `zhipuai/` |
| Zhipu AI Coding Plan | `zhipuai-coding-plan` | `https://open.bigmodel.cn/api/coding/paas/v4` | `ZHIPUAI_CODING_PLAN_BASE_URL` | `ZHIPU_API_KEY` | `zhipuai-coding-plan/` |
<!-- END GENERATED PROVIDER TABLE -->

Each catalog row's base URL is overridable through the env var in its
**Base-URL override** column, for self-hosted or private-link deployments.

The **Credential env var** column names each native adapter's *primary*
credential. Bedrock, Azure and Vertex each need more than that one value — see
[Provider-specific behavior](#provider-specific-behavior) below.

## Routing

Tracelane routes by model-string prefix. Examples:

```
claude-sonnet-4.5                → Anthropic
gpt-5-codex                      → OpenAI
gemini-3-pro                     → Google
bedrock/anthropic.claude-3-5...  → AWS Bedrock
azure/gpt-4o-mini                → Azure OpenAI
together/Qwen2.5-72B-Instruct    → Together AI
groq/llama-3.3-70b-versatile     → Groq
ollama/llama3.2:3b               → local Ollama
```

If your model name doesn't match a built-in prefix, set the routing
explicitly in `tracelane.yaml`:

```yaml
models:
  my-internal-fast:
    provider: groq
    model: llama-3.3-70b-versatile
  my-internal-smart:
    provider: anthropic
    model: claude-sonnet-4.5
```

Only `provider` and `model` are read inside a model alias. Any other key is a
parse error, and a `tracelane.yaml` that fails to parse is a **startup refusal** —
the gateway will not boot on a half-applied routing table.

## Failover

Configure a fallback chain per logical model. If the primary returns 5xx,
429, or times out past the configured budget, we try the next provider in
the chain — same request, translated to the target provider's wire format.

```yaml
failover:
  chain: anthropic, vertex:vertex/gemini-2.5-flash-lite
  retries: 2
  backoff_ms: 50
```

The chain is a **top-level `failover:` block**, not a per-model one. A bare hop
(`anthropic`) is allowed only for providers with a built-in default model;
every other hop names its model as `provider:model`. Failover is **opt-in per
request** via the `X-Tracelane-Failover: cross-provider` header and off by
default, and it fires on 500/502/503/504 — a 429 is returned to you with
`Retry-After` rather than retried elsewhere.

The recommended production fallback chain is **Anthropic Sonnet → OpenAI
gpt-5 → Gemini 3 Pro**. `X-Tracelane-Failover` is a REQUEST header you send to opt in; the gateway
does not add it to the response. When a fallback serves the request, the hop is
recorded on the trace span rather than in a response header.

See [`crates/gateway/src/providers/failover.rs`](../../crates/gateway/src/providers/failover.rs) for the implementation.

## BYOK only (V1)

V1 ships **bring-your-own-key (BYOK) only**. Provider API keys are
envelope-encrypted (AEAD) at rest — AES-256-GCM via `ring`, bound to
`(tenant_id, provider_id)` by AAD — and decrypted in-memory just-in-time
on dispatch — they never appear in logs, spans, or error messages. The
`tracing` redaction filter strips them from any structured field that lands
in OTLP exports.

**No managed billing for upstream providers in V1.** You bring your own
provider keys; Tracelane bills only for its gateway/observability/audit
SKUs. The same envelope-encryption flow accepts AWS/Azure credentials for
Bedrock and Azure OpenAI respectively.

## Provider-specific behavior

### Anthropic
- Native `/v1/messages` is the canonical endpoint. We translate from OpenAI
  shape on `/v1/chat/completions` if the model is `claude-*`.
- `prompt_caching` is preserved (`cache_control` blocks pass through).
- `tool_use` blocks pass through unchanged.

### OpenAI
- `/v1/chat/completions` is the only completion route.
- Function calling preserved across the failover chain.

### Google Gemini (AI Studio)
- Multi-modal parts (image, audio, video) supported.
- `safetySettings` and `generationConfig` pass through.
- Counts as multi-modal billing if any non-text part is present.

### Google Vertex AI
- Same Gemini model IDs, a different product. `vertex/*` is matched before
  `gemini*`, which is what keeps `vertex/gemini-2.5-pro` off the AI Studio
  adapter.
- The credential is a whole GCP service-account JSON, not an API key — Vertex
  rejects API keys outright. Paste the JSON as the credential; the project is
  read from it.
- Billed to the linked Cloud project, so Google Cloud credits pay for Vertex and
  not for AI Studio.

### AWS Bedrock
- SigV4 signing inline, no `aws-sdk-rust` dependency (keeps gateway size down).
- Needs `AWS_SECRET_ACCESS_KEY` alongside the `AWS_ACCESS_KEY_ID` in the table.
- Per-region routing via `AWS_REGION`.
- Converse API is the unified entry; legacy InvokeModel falls back per model.

### Azure OpenAI
- Needs `AZURE_OPENAI_ENDPOINT` alongside the API key; `AZURE_OPENAI_API_VERSION`
  is optional and defaults to `2025-01-01-preview`.
- Deployment names route through `AZURE_OPENAI_ENDPOINT/openai/deployments/<name>`.
- Map deployment name → logical model in `tracelane.yaml`.

### Cohere
- Native `/v2/chat` for chat completions, `/v2/rerank` for reranking.
- Reranking emits its own span type (`cohere.rerank`) and is observable.

### Ollama (local)
- Defaults to `localhost:11434` — meant for local dev, never production.
- Skips BYOK envelope (no key to encrypt).

## Smoke tests

Each adapter has a wiremock-backed smoke test in
[`crates/gateway/src/providers/smoke_tests.rs`](../../crates/gateway/src/providers/smoke_tests.rs):
single-shot completion, streaming, tool-use, error mapping. Run with:

```bash
cargo test -p gateway providers::smoke_tests
```

These run with `MOCK_PROVIDERS=1` and never hit the real network — they
catch wire-format drift before it reaches a customer.

## Adding a new provider

1. If OpenAI-compatible: it is a row in `crates/gateway/providers.tsv`, not
   Rust. Run `python3 scripts/ci/build-provider-catalog.py` — it picks up any
   OpenAI-compatible provider the upstream catalog carries and gives it a
   namespaced `<id>/` prefix. A row you write by hand survives regeneration:
   rows already in the file are treated as authoritative and are never
   overwritten, because editing one would re-point live traffic.
2. If a custom wire shape: add a dedicated adapter file (`my_provider.rs`)
   alongside `anthropic.rs` / `google.rs`, a field on `ProviderRegistry`, and an
   arm in **both** `provider_id_for_model` and `env_var_for_provider_id`.
3. Add a smoke test in `smoke_tests.rs`.
4. Re-run the generator. The tables on this page, the model price table and the
   dashboard's BYOK dropdown all come from the same two sources, so this is the
   step that keeps them from disagreeing. **Do not hand-edit the table above** —
   anything between the markers is overwritten.
5. ADR if the provider's wire format introduces a new edge case (e.g.,
   non-JSON streaming, non-standard tool format).

## Related

- [API reference](./api-reference.md) — the `/v1/chat/completions` surface
- [Architecture](./architecture.md) — gateway data flow
- [`crates/gateway/src/providers/`](../../crates/gateway/src/providers/) — adapters source
- ADR-006 — BYOK envelope encryption (see the ADR index in the docs site) — key handling
