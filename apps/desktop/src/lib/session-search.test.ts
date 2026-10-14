import { describe, expect, it } from 'vitest'

import type { SessionInfo } from '@/types/hermes'

import { sessionMatchesSearch } from './session-search'

function makeSession(overrides: Partial<SessionInfo> = {}): SessionInfo {
  return {
    archived: false,
    cwd: '/home/user/projects/hermes-agent',
    ended_at: null,
    id: '20260603_090200_abcd12',
    input_tokens: 0,
    is_active: false,
    last_active: 1_000,
    message_count: 2,
    model: 'claude',
    output_tokens: 0,
    preview: 'Fix Desktop session search',
    source: 'cli',
    started_at: 1_000,
    title: 'Desktop Search Feature',
    tool_call_count: 0,
    ...overrides
  }
}

describe('sessionMatchesSearch', () => {
  it('matches loaded sessions by full and partial session id', () => {
    const session = makeSession()

    expect(sessionMatchesSearch(session, '20260603_090200_abcd12')).toBe(true)
    expect(sessionMatchesSearch(session, '090200')).toBe(true)
    expect(sessionMatchesSearch(session, 'ABCD12')).toBe(true)
  })

  it('matches projected compression sessions by lineage root id', () => {
    const session = makeSession({
      _lineage_root_id: '20260602_235959_root99',
      id: '20260603_010000_tip01'
    })

    expect(sessionMatchesSearch(session, 'root99')).toBe(true)
    expect(sessionMatchesSearch(session, '20260602')).toBe(true)
  })

  it('preserves title, preview, and workspace matching', () => {
    const session = makeSession()

    expect(sessionMatchesSearch(session, 'desktop search')).toBe(true)
    expect(sessionMatchesSearch(session, 'session search')).toBe(true)
    expect(sessionMatchesSearch(session, 'hermes-agent')).toBe(true)
  })

  it('matches sessions by git branch', () => {
    expect(sessionMatchesSearch(makeSession({ git_branch: 'feat/cool-thing' }), 'feat/cool-thing')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ git_branch: 'feat/cool-thing' }), 'cool')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ git_branch: 'main' }), 'main')).toBe(true)
  })

  it('matches sessions by source platform and aliases', () => {
    expect(sessionMatchesSearch(makeSession({ source: 'telegram' }), 'Telegram')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ source: 'whatsapp' }), 'WhatsApp')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ source: 'whatsapp' }), 'wa')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ source: 'slack' }), 'slack')).toBe(true)
    expect(sessionMatchesSearch(makeSession({ source: 'bluebubbles' }), 'imessage')).toBe(true)
  })

  it('narrows by all search words across title, workspace, branch, source, and identity', () => {
    const session = makeSession({
      source: 'telegram',
      git_branch: 'feat/search',
      _lineage_root_id: '20260602_root99'
    })

    expect(sessionMatchesSearch(session, 'telegram hermes-agent search')).toBe(true)
    expect(sessionMatchesSearch(session, 'ROOT99 feature feat/search')).toBe(true)
    expect(sessionMatchesSearch(session, 'search telegram missing')).toBe(false)
    expect(sessionMatchesSearch(session, 'desktop telegram')).toBe(true)
    expect(sessionMatchesSearch(makeSession(), 'desktop telegram')).toBe(false)
  })

  it('ignores word order, repeated words, and extra whitespace', () => {
    const session = makeSession({ source: 'telegram', git_branch: 'feat/search' })

    expect(sessionMatchesSearch(session, '  SEARCH\ttelegram\nhermes-agent  ')).toBe(true)
    expect(sessionMatchesSearch(session, 'telegram search search')).toBe(true)
  })

  it.each(['', ' ', '\t\n'])('keeps all sessions for an empty query (%j)', query => {
    expect(sessionMatchesSearch(makeSession(), query)).toBe(true)
  })

  it('matches partial words without treating punctuation as search syntax', () => {
    const session = makeSession({ git_branch: 'feat/search' })

    expect(sessionMatchesSearch(session, 'feat/ hermes-')).toBe(true)
    expect(sessionMatchesSearch(session, 'feat/*')).toBe(false)
    expect(sessionMatchesSearch(session, 'desktop | unrelated')).toBe(false)
  })

  it('requires every clue to belong to the same session when filtering a list', () => {
    const matching = makeSession({ source: 'telegram', git_branch: 'feat/search' })

    const sessions = [
      makeSession({ id: 'wrong-workspace', source: 'telegram', cwd: '/projects/other' }),
      matching,
      makeSession({ id: 'wrong-source', source: 'slack', git_branch: 'feat/search' })
    ]

    expect(sessions.filter(session => sessionMatchesSearch(session, 'telegram hermes-agent search'))).toEqual([
      matching
    ])
  })

  it('handles absent optional metadata and searches the preview fallback', () => {
    const session = makeSession({ title: null, preview: 'Recover history', cwd: undefined, source: undefined })

    expect(sessionMatchesSearch(session, 'history recover')).toBe(true)
    expect(sessionMatchesSearch(session, 'recover telegram')).toBe(false)
    expect(sessionMatchesSearch(session, 'recover hermes-agent')).toBe(false)
  })

  it('does not match unrelated queries', () => {
    expect(sessionMatchesSearch(makeSession(), 'totally-unrelated')).toBe(false)
  })
})
