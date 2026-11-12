# Không merge nhánh `feature/68-vmware-lab` vào `main`

File này không có `paths:` nên luôn được nạp. Bổ sung cho `.claude/rules/git-workflow.md`.

- KHÔNG merge `feature/68-vmware-lab` (PLAN-008, issue #68) vào `main`, dưới bất kỳ hình thức nào: `git merge`, `git pull` kéo nhánh này vào `main`, `gh pr merge`, hay nút merge trên GitHub do Claude thao tác.
- Nhánh này đang được thử trên Docker lab và 3 máy ảo VMware. Nó chỉ được merge khi người dùng nói rõ, trong lượt hiện tại, rằng đã thử xong và cho phép merge.
- Được phép (khi người dùng cho phép commit/push như `git-workflow.md` yêu cầu): commit và push lên chính nhánh `feature/68-vmware-lab`, và đồng bộ `main` vào nhánh này (`git merge main` khi đang đứng ở nhánh này) để cập nhật. Chiều ngược lại (nhánh này vào `main`) thì không.
- Mở pull request vào `main` thì được, nhưng chỉ để review; không tự merge PR.
- Gỡ file này khi PLAN-008 sang `DONE` hoặc người dùng không còn muốn chặn.
