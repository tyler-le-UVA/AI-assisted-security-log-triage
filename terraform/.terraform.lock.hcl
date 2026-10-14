cd ~/projects/aws-security-triage
git pull
pbpaste > terraform/.terraform.lock.hcl
git add terraform/.terraform.lock.hcl
git commit -m "Add Terraform provider lock file"
git push