./run_all_gates.sh
echo "Badge: $(cat badge.txt)"
cat pr_comment.md


Add a stage after running gates:

./run_all_gates.sh
./rollup_gates.sh
./summarize_gates.sh || true
cat pr_comment.md


