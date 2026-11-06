from passwordmanager.core.audit import audit
from passwordmanager.core.vault import Entry

STRONG = "q7#Lm9!vXz2@Rw5$"


def test_reused_passwords_are_grouped_by_name():
    report = audit([
        Entry("github", password=STRONG), Entry("gitlab", password=STRONG),
        Entry("bank", password="another-Strong-1!x"),
    ])
    assert report.reused == [["github", "gitlab"]]
    assert report.weak == []


def test_short_or_low_entropy_passwords_are_weak():
    report = audit([Entry("a", password="password1"), Entry("b", password=STRONG),
                    Entry("c", password="a" * 30), Entry("d", password="Xk9#mQ2$" * 4)])
    assert [name for name, _ in report.weak] == ["a", "c", "d"]


def test_entries_without_a_password_are_reported_not_flagged():
    report = audit([Entry("wifi-note", notes="hello"), Entry("x", password=STRONG)])
    assert report.no_password == ["wifi-note"]
    assert not report.has_issues


def test_empty_vault_has_no_issues():
    assert not audit([]).has_issues


def test_pattern_detector():
    from passwordmanager.core.audit import looks_patterned

    assert looks_patterned("aaaaaaaaaaaa") and looks_patterned("abcdefabcdefabcdef")
    assert not looks_patterned(STRONG)
