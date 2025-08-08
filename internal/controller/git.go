package controller

import (
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var ErrNoChanges = errors.New("no-changes")
var customClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

var projectPath = "compute/ocpbm-cluster-config"

func cloneRepo() error {
	_, err := git.PlainClone("/repo", false, &git.CloneOptions{
		URL: "https://gitlab.med.one/compute/ocpbm-cluster-config.git",
		Auth: &githttp.BasicAuth{
			Username: "orrener",
			Password: "yMSEgyBKpAsjT_ziK2no",
		},
		InsecureSkipTLS: true,
	})
	if err != nil {
		return err
	}
	return nil
}

func CheckoutBranch(branchName string) (*git.Repository, *git.Worktree, error) {

	var branchRef = plumbing.NewBranchReferenceName(branchName)

	repo, err := git.PlainOpen("/repo")
	if err != nil {
		return nil, nil, err
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, nil, err
	}

	err = wt.Checkout(&git.CheckoutOptions{
		Branch: branchRef,
		Create: true,
	})
	if err != nil {
		return nil, nil, err
	}
	return repo, wt, nil
}

func commitAndPushChanges(wt *git.Worktree, repo *git.Repository, branchName string) error {

	var branchRef = plumbing.NewBranchReferenceName(branchName)

	err := wt.AddWithOptions(&git.AddOptions{All: true})
	if err != nil {
		return err
	}

	_, err = wt.Commit("Created certificates automatically", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Or Rener",
			Email: "orrener2000or@gmail.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			return ErrNoChanges
		}
		return err
	}
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs: []config.RefSpec{
			config.RefSpec("refs/heads/" + branchName + ":refs/heads/" + branchName),
		},
		Auth: &githttp.BasicAuth{
			Username: "orrener",
			Password: "yMSEgyBKpAsjT_ziK2no",
		},
		InsecureSkipTLS: true,
		Force:           true,
	})
	if err != nil {
		return err
	}
	err = repo.Storer.RemoveReference(branchRef)
	if err != nil {
		return err
	}
	return nil
}

func createMergeRequest(sourceBranch string) (string, error) {
	git, err := gitlab.NewClient("yMSEgyBKpAsjT_ziK2no", gitlab.WithBaseURL("https://gitlab.med.one/api/v4"), gitlab.WithHTTPClient(customClient))
	if err != nil {
		return "", err
	}

	title := "Auto-renewed certs"
	targetBranch := "main"
	description := "This MR was auto-created to renew certificates."
	removeSourceBranch := true

	mrExists, IID, err := DoesMRExist(git, sourceBranch, targetBranch)
	if err != nil {
		return "", err
	}
	if mrExists {
		updatedTitle := "Updated: Auto-renewed certs"
		updatedDescription := "This MR was updated to include renewed certificates."

		updatedMR, _, err := git.MergeRequests.UpdateMergeRequest(projectPath, IID, &gitlab.UpdateMergeRequestOptions{
			Title:       &updatedTitle,
			Description: &updatedDescription,
		})
		if err != nil {
			return "", err
		}

		return updatedMR.WebURL, nil
	}

	mr, _, err := git.MergeRequests.CreateMergeRequest(projectPath, &gitlab.CreateMergeRequestOptions{
		Title:              &title,
		SourceBranch:       &sourceBranch,
		TargetBranch:       &targetBranch,
		Description:        &description,
		RemoveSourceBranch: &removeSourceBranch,
	})
	if err != nil {
		return "", err
	}
	return mr.WebURL, nil
}

func DoesMRExist(git *gitlab.Client, sourceBranch string, targetBranch string) (bool, int, error) {

	mrs, _, err := git.MergeRequests.ListProjectMergeRequests(projectPath, &gitlab.ListProjectMergeRequestsOptions{
		SourceBranch: &sourceBranch,
		TargetBranch: &targetBranch,
		State:        gitlab.Ptr("opened"),
	})
	if err != nil {
		return false, 0, err
	}
	if len(mrs) == 0 {
		return false, 0, nil
	}
	return true, mrs[0].IID, nil
}

func DeleteDirContents(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(path, entry.Name())
		err := os.RemoveAll(path)
		if err != nil {
			return err
		}
	}
	return nil
}

func WriteToFile(path string, content []byte) error {
	err := os.WriteFile(path, content, 0600)
	if err != nil {
		return err
	}
	return nil
}
