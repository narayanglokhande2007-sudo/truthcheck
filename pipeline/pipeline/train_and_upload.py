import json, os, torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer, DataCollatorForLanguageModeling
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset
from huggingface_hub import HfApi, upload_folder
import shutil

# 1. Load weekly training data
data_path = 'pipeline/daily-data/weekly_scam_data.jsonl'
texts = []
with open(data_path, 'r', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line)
        msgs = entry.get("messages", [])
        prompt = ""
        for m in msgs:
            role = m["role"]
            content = m["content"]
            if role == "system": prompt += f"System: {content}\n"
            elif role == "user": prompt += f"User: {content}\n"
            elif role == "assistant": prompt += f"Assistant: {content}\n"
        texts.append(prompt.strip())

dataset = Dataset.from_dict({"text": texts})

# 2. Load base model (no GPU available, CPU only)
model_name = "distilgpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
tokenizer.pad_token = tokenizer.eos_token
model = AutoModelForCausalLM.from_pretrained(model_name)

# 3. LoRA config
lora_config = LoraConfig(
    r=4, lora_alpha=8, target_modules=["c_attn"],
    lora_dropout=0.05, bias="none", task_type=TaskType.CAUSAL_LM
)
model = get_peft_model(model, lora_config)

# 4. Tokenize
def tokenize_function(examples):
    return tokenizer(examples["text"], truncation=True, max_length=256, padding="max_length")
tokenized_dataset = dataset.map(tokenize_function, batched=True)

# 5. Training arguments (CPU friendly)
training_args = TrainingArguments(
    output_dir="./scam-detector-weekly",
    num_train_epochs=2,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    save_steps=100,
    logging_steps=50,
    learning_rate=5e-5,
    report_to="none",
    fp16=False,
    no_cuda=True
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
    data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
)
trainer.train()

# 6. Merge and save full model
merged_model = model.merge_and_unload()
merged_model.save_pretrained("./merged-scam-model-weekly")
tokenizer.save_pretrained("./merged-scam-model-weekly")

# 7. Upload to Hugging Face (overwrite)
HF_TOKEN = os.environ['HF_TOKEN']
repo_id = "VerifyPulse384556/verifypulse-scam-detector"
api = HfApi()
api.delete_folder(repo_id=repo_id, path_in_repo="", token=HF_TOKEN)  # clear old files
upload_folder(
    folder_path="./merged-scam-model-weekly",
    repo_id=repo_id,
    token=HF_TOKEN,
    repo_type="model",
    commit_message="🤖 Weekly automated retraining"
)
print("✅ Weekly retraining complete and model uploaded!")
