# Homebrew formula for blastcheck.
#
# Lives here rather than in a tap repo so it is version-controlled beside the
# thing it installs. To publish: create `prococonsulting/homebrew-tap`, copy this
# to `Formula/blastcheck.rb`, and update `url`/`sha256` on each release —
# `contrib/update-formula.sh` does that from the published PyPI sdist.
#
# Then: brew install prococonsulting/tap/blastcheck
#
# blastcheck has no runtime dependencies, so this is a plain virtualenv install
# with nothing to vendor. That is worth keeping true.
class Blastcheck < Formula
  include Language::Python::Virtualenv

  desc "Emit an Impact Manifest change-safety assertion from a Terraform plan"
  homepage "https://blastcheck.dev"
  url "PLACEHOLDER_URL"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"
  head "https://github.com/prococonsulting/blastcheck.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    # Not a smoke test of --version alone: prove the packaged data files came
    # along, since a wheel missing its schema or packs installs perfectly and
    # then cannot do its job. That exact bug shipped once as 0.1.0.
    assert_match "blastcheck", shell_output("#{bin}/blastcheck --version")
    assert_match "Provider packs", shell_output("#{bin}/blastcheck rules")

    (testpath/"plan.json").write <<~JSON
      {"format_version":"1.2","resource_changes":[
        {"address":"aws_ebs_volume.d","type":"aws_ebs_volume","name":"d",
         "change":{"actions":["update"],"before":{"size":100},"after":{"size":500}}}]}
    JSON
    out = shell_output("#{bin}/blastcheck #{testpath}/plan.json --json")
    assert_match "impact", out.downcase
    assert_match "irreversible", out
  end
end
