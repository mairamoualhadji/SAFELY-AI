namespace SafelyAI.AI.Conversation;

public sealed record AssistantReply(
    string Answer,
    bool UsedLocalModel,
    DateTime CreatedAt);
