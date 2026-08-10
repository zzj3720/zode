import { profileIsUsableOnEndpoint, type AuthProfile, type Provider } from "./provider";

export type ExecutionChoice = Readonly<{
  key: string;
  provider: Provider;
  model: string;
  profile: AuthProfile;
  label: string;
}>;

export type ModelExecutionGroup = Readonly<{
  model: string;
  choices: readonly ExecutionChoice[];
}>;

export function modelExecutionGroups(
  providers: readonly Provider[],
  endpointId: string,
): readonly ModelExecutionGroup[] {
  if (!endpointId) return [];
  const groups = new Map<string, ExecutionChoice[]>();
  for (const provider of providers) {
    const profiles = provider.profiles.value.filter((profile) =>
      profileIsUsableOnEndpoint(profile, endpointId),
    );
    for (const model of provider.data.value.descriptor.models) {
      const choices = groups.get(model) ?? [];
      for (const profile of profiles) {
        choices.push({
          key: `${provider.name}:${profile.id}`,
          provider,
          model,
          profile,
          label: profile.displayLabel.value,
        });
      }
      if (choices.length > 0) groups.set(model, choices);
    }
  }
  return [...groups].map(([model, choices]) => {
    const providerCount = new Set(choices.map((choice) => choice.provider.name)).size;
    return {
      model,
      choices: choices.map((choice) => ({
        ...choice,
        label: providerCount > 1 ? `${choice.provider.name} · ${choice.label}` : choice.label,
      })),
    };
  });
}

export function executionChoiceMatches(
  choice: ExecutionChoice | null | undefined,
  provider: string | undefined,
  model: string | undefined,
  profileId: string | undefined,
): boolean {
  if (!choice) return false;
  const profile = choice.profile.data.value;
  return (
    choice.provider.name === provider &&
    choice.model === model &&
    (profile.auth_profile_id === profileId || profile.profile_id === profileId)
  );
}
